package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	analysisv1 "github.com/glaslos/backstreet/gen/go/v1"
	"github.com/glaslos/backstreet/internal/analysis"
	"github.com/glaslos/backstreet/internal/auth"
	"github.com/glaslos/backstreet/internal/blob"
	"github.com/glaslos/backstreet/internal/config"
	"github.com/glaslos/backstreet/internal/grpcapi"
	"github.com/glaslos/backstreet/internal/httpapi"
	"github.com/glaslos/backstreet/internal/mcpapi"
	"github.com/glaslos/backstreet/internal/metrics"
	"github.com/glaslos/backstreet/internal/store"
	"github.com/glaslos/backstreet/internal/worker"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		response, err := http.Get("http://127.0.0.1:8080/healthz")
		if err != nil || response.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		_ = response.Body.Close()
		return
	}
	if err := run(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.DatabasePath), 0o750); err != nil {
		return err
	}
	db, err := store.Open(cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer db.Close()
	blobs, err := blob.New(filepath.Join(cfg.DataDir, "blobs"))
	if err != nil {
		return err
	}
	authenticator, err := auth.New(cfg.APIKeyHashes, cfg.RequestsPerMin)
	if err != nil {
		return err
	}
	service := analysis.NewService(db, blobs, worker.New(cfg.WorkerSocket), cfg.DataDir, cfg.MaxUploadBytes, cfg.MaxQueueDepth)
	metrics.RegisterQueueDepth(db.QueueDepth)
	httpAPI := httpapi.New(service, cfg.MaxUploadBytes)
	mcpAPI := mcpapi.New(service, cfg.MaxUploadBytes)

	root := chi.NewRouter()
	root.Use(requestLog)
	root.Get("/healthz", httpAPI.Health)
	root.Method(http.MethodGet, "/metrics", promhttp.Handler())
	root.Handle("/v1/*", authenticator.HTTP(httpAPI.Routes()))
	root.Handle("/mcp", authenticator.HTTP(mcpAPI.Handler()))
	httpServer := &http.Server{
		Addr: cfg.HTTPAddr, Handler: root, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Minute, WriteTimeout: 15 * time.Minute, IdleTimeout: 60 * time.Second,
	}

	grpcListener, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		return err
	}
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(authenticator.UnaryInterceptor),
		grpc.StreamInterceptor(authenticator.StreamInterceptor),
		grpc.MaxRecvMsgSize(int(cfg.MaxUploadBytes+1<<20)),
		grpc.MaxSendMsgSize(128<<20),
	)
	analysisv1.RegisterAnalysisServiceServer(grpcServer, grpcapi.New(service))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errs := make(chan error, 3)
	go func() { errs <- service.Run(ctx, cfg.MaxConcurrent) }()
	go service.Retain(ctx, cfg.Retention)
	go authenticator.Cleanup(ctx)
	go func() {
		slog.Info("HTTP and MCP server listening", "address", cfg.HTTPAddr)
		errs <- httpServer.ListenAndServe()
	}()
	go func() {
		slog.Info("gRPC server listening", "address", cfg.GRPCAddr)
		errs <- grpcServer.Serve(grpcListener)
	}()

	select {
	case <-ctx.Done():
	case err = <-errs:
		if !errors.Is(err, http.ErrServerClosed) && err != nil {
			stop()
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
	stopped := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-shutdownCtx.Done():
		grpcServer.Stop()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		slog.Info("request", "method", r.Method, "path", r.URL.Path, "duration_ms", time.Since(started).Milliseconds())
	})
}
