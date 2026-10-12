package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"time"

	analysisv1 "github.com/glaslos/backstreet/gen/go/v1"
	"github.com/glaslos/backstreet/internal/analysis"
	"github.com/glaslos/backstreet/internal/store"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type Server struct {
	service   *analysis.Service
	maxUpload int64
}

func New(service *analysis.Service, maxUpload int64) *Server {
	return &Server{service: service, maxUpload: maxUpload}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/analyses", s.submit)
	mux.HandleFunc("GET /v1/analyses", s.list)
	mux.HandleFunc("GET /v1/analyses/{id}", s.get)
	mux.HandleFunc("POST /v1/analyses/{id}/cancel", s.cancel)
	mux.HandleFunc("GET /v1/analyses/{id}/report", s.report)
	mux.HandleFunc("GET /v1/analyses/{id}/artifacts", s.artifacts)
	mux.HandleFunc("GET /v1/analyses/{id}/artifacts/{artifact}", s.downloadArtifact)
	return mux
}

func (s *Server) submit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.maxUpload+(1<<20))
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		writeError(w, err)
		return
	}
	defer r.MultipartForm.RemoveAll()
	file, header, err := r.FormFile("sample")
	if err != nil {
		writeError(w, analysis.ErrInvalid)
		return
	}
	defer file.Close()
	options := &analysisv1.AnalysisOptions{}
	if raw := r.FormValue("options"); raw != "" {
		if err := protojson.Unmarshal([]byte(raw), options); err != nil {
			writeError(w, errors.Join(analysis.ErrInvalid, err))
			return
		}
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	result, err := s.service.Submit(r.Context(), header.Filename, idempotencyKey, options, file)
	if err != nil {
		writeError(w, err)
		return
	}
	writeProto(w, http.StatusAccepted, result)
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	size, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	items, next, err := s.service.List(r.Context(), size, r.URL.Query().Get("page_token"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeProto(w, http.StatusOK, &analysisv1.ListAnalysesResponse{Analyses: items, NextPageToken: next})
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	result, err := s.service.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeProto(w, http.StatusOK, result)
}

func (s *Server) cancel(w http.ResponseWriter, r *http.Request) {
	result, err := s.service.Cancel(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeProto(w, http.StatusOK, result)
}

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	result, err := s.service.Report(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeProto(w, http.StatusOK, result)
}

func (s *Server) artifacts(w http.ResponseWriter, r *http.Request) {
	items, err := s.service.Artifacts(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	response := &analysisv1.ListArtifactsResponse{}
	for _, item := range items {
		response.Artifacts = append(response.Artifacts, &analysisv1.Artifact{
			Id:          item.ID,
			AnalysisId:  item.AnalysisID,
			Kind:        item.Kind,
			Name:        item.Name,
			Sha256:      item.SHA256,
			Size:        uint64(item.Size),
			ContentType: item.ContentType,
		})
	}
	writeProto(w, http.StatusOK, response)
}

func (s *Server) downloadArtifact(w http.ResponseWriter, r *http.Request) {
	item, reader, err := s.service.Artifact(r.Context(), r.PathValue("id"), r.PathValue("artifact"))
	if err != nil {
		writeError(w, err)
		return
	}
	defer reader.Close()
	w.Header().Set("Content-Type", item.ContentType)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": item.Name}))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.FormatInt(item.Size, 10))
	_, _ = io.Copy(w, reader)
}

func (s *Server) Health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, time.Second)
	defer cancel()
	ready := s.service.WorkerReady(ctx)
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "worker_ready": ready})
}

func (s *Server) Metrics(w http.ResponseWriter, r *http.Request) {
	metrics := s.service.Metrics(r.Context())
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = fmt.Fprintf(w, `# TYPE backstreet_analyses_submitted_total counter
backstreet_analyses_submitted_total %d
# TYPE backstreet_analyses_running gauge
backstreet_analyses_running %d
# TYPE backstreet_analyses_queued gauge
backstreet_analyses_queued %d
# TYPE backstreet_analyses_succeeded_total counter
backstreet_analyses_succeeded_total %d
# TYPE backstreet_analyses_failed_total counter
backstreet_analyses_failed_total %d
# TYPE backstreet_analyses_cancelled_total counter
backstreet_analyses_cancelled_total %d
`, metrics.Submitted, metrics.Running, metrics.Queued, metrics.Succeeded, metrics.Failed, metrics.Cancelled)
}

func contextWithTimeout(r *http.Request, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), timeout)
}

func writeProto(w http.ResponseWriter, code int, value proto.Message) {
	data, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(value)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(append(data, '\n'))
}

func writeError(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	switch {
	case errors.Is(err, store.ErrNotFound):
		code = http.StatusNotFound
	case errors.Is(err, analysis.ErrInvalid):
		code = http.StatusBadRequest
	case errors.Is(err, analysis.ErrQueueFull):
		code = http.StatusTooManyRequests
	case errors.Is(err, analysis.ErrConflict):
		code = http.StatusConflict
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": http.StatusText(code), "message": err.Error()})
}
