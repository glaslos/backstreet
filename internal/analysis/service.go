package analysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	analysisv1 "github.com/glaslos/backstreet/gen/go/v1"
	"github.com/glaslos/backstreet/internal/blob"
	"github.com/glaslos/backstreet/internal/store"
	"github.com/glaslos/backstreet/internal/worker"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	ErrInvalid   = errors.New("invalid request")
	ErrQueueFull = errors.New("analysis queue is full")
	ErrConflict  = errors.New("analysis state conflict")
)

type Service struct {
	store      *store.Store
	blobs      *blob.Store
	worker     *worker.Client
	dataDir    string
	maxUpload  int64
	maxQueue   int
	wake       chan struct{}
	cancelMu   sync.Mutex
	cancelJobs map[string]context.CancelFunc
	submitted  atomic.Uint64
	running    atomic.Int64
	succeeded  atomic.Uint64
	failed     atomic.Uint64
	cancelled  atomic.Uint64
}

type Metrics struct {
	Submitted uint64
	Running   int64
	Succeeded uint64
	Failed    uint64
	Cancelled uint64
	Queued    int
}

func NewService(db *store.Store, blobs *blob.Store, workerClient *worker.Client, dataDir string, maxUpload int64, maxQueue int) *Service {
	return &Service{
		store: db, blobs: blobs, worker: workerClient, dataDir: dataDir,
		maxUpload: maxUpload, maxQueue: maxQueue, wake: make(chan struct{}, 1),
		cancelJobs: make(map[string]context.CancelFunc),
	}
}

func (s *Service) Submit(ctx context.Context, filename, idempotencyKey string, options *analysisv1.AnalysisOptions, sample io.Reader) (*analysisv1.Analysis, error) {
	if err := validateFilename(filename); err != nil {
		return nil, err
	}
	options = normalizeOptions(options)
	if err := validateOptions(options); err != nil {
		return nil, err
	}
	depth, err := s.store.QueueDepth(ctx)
	if err != nil {
		return nil, err
	}
	if depth >= s.maxQueue {
		return nil, ErrQueueFull
	}
	hash, size, err := s.blobs.Put(sample, s.maxUpload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if size == 0 {
		return nil, fmt.Errorf("%w: empty sample", ErrInvalid)
	}
	a := &analysisv1.Analysis{
		Id:           uuid.NewString(),
		State:        analysisv1.AnalysisState_ANALYSIS_STATE_QUEUED,
		Filename:     filepath.Base(filename),
		SampleSha256: hash,
		SampleSize:   uint64(size),
		Options:      options,
		CreatedAt:    timestamppb.Now(),
	}
	a, err = s.store.Create(ctx, a, idempotencyKey)
	if err == nil {
		s.submitted.Add(1)
		s.signal()
	}
	return a, err
}

func (s *Service) Get(ctx context.Context, id string) (*analysisv1.Analysis, error) {
	return s.store.Get(ctx, id)
}

func (s *Service) List(ctx context.Context, size int, token string) ([]*analysisv1.Analysis, string, error) {
	return s.store.List(ctx, size, token)
}

func (s *Service) Cancel(ctx context.Context, id string) (*analysisv1.Analysis, error) {
	before, err := s.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	s.cancelMu.Lock()
	cancel := s.cancelJobs[id]
	s.cancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
	result, err := s.store.Cancel(ctx, id)
	if err == nil && before.State != analysisv1.AnalysisState_ANALYSIS_STATE_CANCELLED &&
		result.State == analysisv1.AnalysisState_ANALYSIS_STATE_CANCELLED {
		s.cancelled.Add(1)
	}
	return result, err
}

func (s *Service) Report(ctx context.Context, id string) (*analysisv1.Report, error) {
	hash, err := s.store.ReportHash(ctx, id)
	if err != nil {
		return nil, err
	}
	if hash == "" {
		return nil, ErrConflict
	}
	file, err := s.blobs.Open(hash)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var raw map[string]any
	dec := json.NewDecoder(io.LimitReader(file, 128<<20))
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	document, err := structpb.NewStruct(raw)
	if err != nil {
		return nil, err
	}
	version, _ := raw["report_version"].(string)
	return &analysisv1.Report{AnalysisId: id, ReportVersion: version, Document: document}, nil
}

func (s *Service) Artifacts(ctx context.Context, id string) ([]store.Artifact, error) {
	if _, err := s.store.Get(ctx, id); err != nil {
		return nil, err
	}
	return s.store.Artifacts(ctx, id)
}

func (s *Service) Artifact(ctx context.Context, analysisID, artifactID string) (store.Artifact, io.ReadCloser, error) {
	a, err := s.store.Artifact(ctx, analysisID, artifactID)
	if err != nil {
		return store.Artifact{}, nil, err
	}
	file, err := s.blobs.Open(a.SHA256)
	return a, file, err
}

func (s *Service) WorkerReady(ctx context.Context) bool {
	return s.worker.Ready(ctx)
}

func (s *Service) Metrics(ctx context.Context) Metrics {
	queued, _ := s.store.QueueDepth(ctx)
	return Metrics{
		Submitted: s.submitted.Load(),
		Running:   s.running.Load(),
		Succeeded: s.succeeded.Load(),
		Failed:    s.failed.Load(),
		Cancelled: s.cancelled.Load(),
		Queued:    queued,
	}
}

func (s *Service) Retain(ctx context.Context, retention time.Duration) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		if err := s.prune(ctx, retention); err != nil && !errors.Is(err, context.Canceled) {
			slog.Error("retention cleanup", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Service) prune(ctx context.Context, retention time.Duration) error {
	if err := s.store.Prune(ctx, time.Now().Add(-retention)); err != nil {
		return err
	}
	hashes, err := s.store.ReferencedHashes(ctx)
	if err != nil {
		return err
	}
	return s.blobs.GC(ctx, hashes)
}

func (s *Service) Run(ctx context.Context, concurrency int) error {
	if err := s.store.Recover(ctx); err != nil {
		return err
	}
	var wg sync.WaitGroup
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runWorker(ctx)
		}()
	}
	s.signal()
	<-ctx.Done()
	wg.Wait()
	return nil
}

func (s *Service) runWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-time.After(time.Second):
		}
		for {
			job, err := s.store.ClaimNext(ctx)
			if errors.Is(err, store.ErrNotFound) {
				break
			}
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					slog.Error("claim analysis", "error", err)
				}
				break
			}
			s.execute(ctx, job)
		}
	}
}

func (s *Service) execute(parent context.Context, job *analysisv1.Analysis) {
	s.running.Add(1)
	defer s.running.Add(-1)
	timeout := time.Duration(job.Options.TimeoutSeconds+10) * time.Second
	ctx, cancel := context.WithTimeout(parent, timeout)
	s.cancelMu.Lock()
	s.cancelJobs[job.Id] = cancel
	s.cancelMu.Unlock()
	defer func() {
		cancel()
		s.cancelMu.Lock()
		delete(s.cancelJobs, job.Id)
		s.cancelMu.Unlock()
	}()

	outputDir := filepath.Join(s.dataDir, "jobs", job.Id)
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		if s.store.Finish(parent, job.Id, analysisv1.AnalysisState_ANALYSIS_STATE_FAILED, "", "storage_error", err.Error()) == nil {
			s.failed.Add(1)
		}
		return
	}
	response, err := s.worker.Analyze(ctx, worker.Request{
		JobID:      job.Id,
		SamplePath: s.blobs.Path(job.SampleSha256),
		OutputDir:  outputDir,
		Options:    job.Options,
	})
	if err != nil {
		state, code := analysisv1.AnalysisState_ANALYSIS_STATE_FAILED, "worker_error"
		if errors.Is(ctx.Err(), context.Canceled) {
			state, code = analysisv1.AnalysisState_ANALYSIS_STATE_CANCELLED, "cancelled"
		} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			code = "timeout"
		}
		if s.store.Finish(parent, job.Id, state, "", code, err.Error()) == nil {
			if state == analysisv1.AnalysisState_ANALYSIS_STATE_CANCELLED {
				s.cancelled.Add(1)
			} else {
				s.failed.Add(1)
			}
		}
		return
	}
	if !response.OK {
		if s.store.Finish(parent, job.Id, analysisv1.AnalysisState_ANALYSIS_STATE_FAILED, "", response.ErrorCode, response.ErrorMessage) == nil {
			s.failed.Add(1)
		}
		return
	}
	reportHash, reportSize, err := putFile(s.blobs, response.ReportPath, 128<<20)
	if err != nil {
		if s.store.Finish(parent, job.Id, analysisv1.AnalysisState_ANALYSIS_STATE_FAILED, "", "report_error", err.Error()) == nil {
			s.failed.Add(1)
		}
		return
	}
	if err := s.store.Finish(parent, job.Id, analysisv1.AnalysisState_ANALYSIS_STATE_SUCCEEDED, reportHash, "", ""); err != nil {
		return
	}
	_ = s.store.AddArtifact(parent, store.Artifact{
		ID:          uuid.NewString(),
		AnalysisID:  job.Id,
		Kind:        "report",
		Name:        "report.json",
		SHA256:      reportHash,
		Size:        reportSize,
		ContentType: "application/json",
	})
	for _, item := range response.Artifacts {
		hash, size, copyErr := putFile(s.blobs, item.Path, s.maxUpload)
		if copyErr != nil {
			slog.Warn("skip worker artifact", "analysis_id", job.Id, "error", copyErr)
			continue
		}
		contentType := item.ContentType
		if contentType == "" {
			contentType = mime.TypeByExtension(filepath.Ext(item.Name))
		}
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		_ = s.store.AddArtifact(parent, store.Artifact{
			ID:          uuid.NewString(),
			AnalysisID:  job.Id,
			Kind:        item.Kind,
			Name:        filepath.Base(item.Name),
			SHA256:      hash,
			Size:        size,
			ContentType: contentType,
		})
	}
	s.succeeded.Add(1)
	_ = os.RemoveAll(outputDir)
}

func (s *Service) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func normalizeOptions(options *analysisv1.AnalysisOptions) *analysisv1.AnalysisOptions {
	if options == nil {
		options = &analysisv1.AnalysisOptions{}
	}
	cloned := proto.Clone(options).(*analysisv1.AnalysisOptions)
	if cloned.Kind == analysisv1.SampleKind_SAMPLE_KIND_UNSPECIFIED {
		cloned.Kind = analysisv1.SampleKind_SAMPLE_KIND_PE
	}
	if cloned.TimeoutSeconds == 0 {
		cloned.TimeoutSeconds = 60
	}
	if cloned.MaxApiCount == 0 {
		cloned.MaxApiCount = 10000
	}
	return cloned
}

func validateOptions(options *analysisv1.AnalysisOptions) error {
	if options.TimeoutSeconds > 600 {
		return fmt.Errorf("%w: timeout_seconds must be <= 600", ErrInvalid)
	}
	if options.MaxApiCount > 1_000_000 {
		return fmt.Errorf("%w: max_api_count is too large", ErrInvalid)
	}
	if len(options.Environment) > 64 || len(options.DnsNames) > 256 || len(options.Argv) > 64 {
		return fmt.Errorf("%w: too many option values", ErrInvalid)
	}
	if options.Kind == analysisv1.SampleKind_SAMPLE_KIND_SHELLCODE &&
		options.Architecture == analysisv1.Architecture_ARCHITECTURE_UNSPECIFIED {
		return fmt.Errorf("%w: shellcode requires architecture", ErrInvalid)
	}
	return nil
}

func validateFilename(filename string) error {
	if filename == "" || len(filename) > 255 || strings.ContainsAny(filename, "\x00\r\n") {
		return fmt.Errorf("%w: invalid filename", ErrInvalid)
	}
	return nil
}

func putFile(blobs *blob.Store, path string, max int64) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	return blobs.Put(file, max)
}
