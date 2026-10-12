package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr        string
	GRPCAddr        string
	WorkerSocket    string
	DataDir         string
	DatabasePath    string
	APIKeyHashes    []string
	MaxUploadBytes  int64
	MaxQueueDepth   int
	MaxConcurrent   int
	RequestsPerMin  int
	Retention       time.Duration
	ShutdownTimeout time.Duration
}

func Load() (Config, error) {
	dataDir := env("BACKSTREET_DATA_DIR", "/data")
	cfg := Config{
		HTTPAddr:        env("BACKSTREET_HTTP_ADDR", ":8080"),
		GRPCAddr:        env("BACKSTREET_GRPC_ADDR", ":9090"),
		WorkerSocket:    env("BACKSTREET_WORKER_SOCKET", "/run/backstreet/worker.sock"),
		DataDir:         dataDir,
		DatabasePath:    env("BACKSTREET_DATABASE_PATH", dataDir+"/backstreet.db"),
		MaxUploadBytes:  envInt64("BACKSTREET_MAX_UPLOAD_BYTES", 64<<20),
		MaxQueueDepth:   envInt("BACKSTREET_MAX_QUEUE_DEPTH", 100),
		MaxConcurrent:   envInt("BACKSTREET_MAX_CONCURRENT", 2),
		RequestsPerMin:  envInt("BACKSTREET_REQUESTS_PER_MINUTE", 120),
		Retention:       time.Duration(envInt("BACKSTREET_RETENTION_HOURS", 168)) * time.Hour,
		ShutdownTimeout: 20 * time.Second,
	}
	for _, hash := range strings.Split(os.Getenv("BACKSTREET_API_KEY_HASHES"), ",") {
		if value := strings.TrimSpace(hash); value != "" {
			cfg.APIKeyHashes = append(cfg.APIKeyHashes, value)
		}
	}
	if len(cfg.APIKeyHashes) == 0 {
		return Config{}, fmt.Errorf("BACKSTREET_API_KEY_HASHES must contain at least one SHA-256 API-key hash")
	}
	return cfg, nil
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(name))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func envInt64(name string, fallback int64) int64 {
	value, err := strconv.ParseInt(os.Getenv(name), 10, 64)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
