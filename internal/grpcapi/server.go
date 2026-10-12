package grpcapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"time"

	analysisv1 "github.com/glaslos/backstreet/gen/go/v1"
	"github.com/glaslos/backstreet/internal/analysis"
	"github.com/glaslos/backstreet/internal/store"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Server struct {
	analysisv1.UnimplementedAnalysisServiceServer
	service *analysis.Service
}

func New(service *analysis.Service) *Server { return &Server{service: service} }

func (s *Server) SubmitAnalysis(stream grpc.ClientStreamingServer[analysisv1.SubmitAnalysisRequest, analysisv1.Analysis]) error {
	var metadata *analysisv1.SubmitMetadata
	var sample bytes.Buffer
	for {
		request, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		switch payload := request.Payload.(type) {
		case *analysisv1.SubmitAnalysisRequest_Metadata:
			if metadata != nil || sample.Len() != 0 {
				return status.Error(codes.InvalidArgument, "metadata must be the first message")
			}
			metadata = payload.Metadata
		case *analysisv1.SubmitAnalysisRequest_Chunk:
			if metadata == nil {
				return status.Error(codes.InvalidArgument, "metadata must be sent first")
			}
			_, _ = sample.Write(payload.Chunk)
		default:
			return status.Error(codes.InvalidArgument, "empty upload message")
		}
	}
	if metadata == nil {
		return status.Error(codes.InvalidArgument, "metadata is required")
	}
	result, err := s.service.Submit(stream.Context(), metadata.Filename, metadata.IdempotencyKey, metadata.Options, &sample)
	if err != nil {
		return mapError(err)
	}
	return stream.SendAndClose(result)
}

func (s *Server) GetAnalysis(ctx context.Context, request *analysisv1.GetAnalysisRequest) (*analysisv1.Analysis, error) {
	result, err := s.service.Get(ctx, request.Id)
	return result, mapError(err)
}

func (s *Server) ListAnalyses(ctx context.Context, request *analysisv1.ListAnalysesRequest) (*analysisv1.ListAnalysesResponse, error) {
	items, next, err := s.service.List(ctx, int(request.PageSize), request.PageToken)
	if err != nil {
		return nil, mapError(err)
	}
	return &analysisv1.ListAnalysesResponse{Analyses: items, NextPageToken: next}, nil
}

func (s *Server) CancelAnalysis(ctx context.Context, request *analysisv1.CancelAnalysisRequest) (*analysisv1.Analysis, error) {
	result, err := s.service.Cancel(ctx, request.Id)
	return result, mapError(err)
}

func (s *Server) GetReport(ctx context.Context, request *analysisv1.GetReportRequest) (*analysisv1.Report, error) {
	result, err := s.service.Report(ctx, request.Id)
	return result, mapError(err)
}

func (s *Server) ListArtifacts(ctx context.Context, request *analysisv1.ListArtifactsRequest) (*analysisv1.ListArtifactsResponse, error) {
	items, err := s.service.Artifacts(ctx, request.AnalysisId)
	if err != nil {
		return nil, mapError(err)
	}
	response := &analysisv1.ListArtifactsResponse{}
	for _, item := range items {
		response.Artifacts = append(response.Artifacts, toProtoArtifact(item))
	}
	return response, nil
}

func (s *Server) DownloadArtifact(request *analysisv1.DownloadArtifactRequest, stream grpc.ServerStreamingServer[analysisv1.ArtifactChunk]) error {
	_, reader, err := s.service.Artifact(stream.Context(), request.AnalysisId, request.ArtifactId)
	if err != nil {
		return mapError(err)
	}
	defer reader.Close()
	buffer := make([]byte, 64<<10)
	for {
		n, readErr := reader.Read(buffer)
		if n > 0 {
			if err := stream.Send(&analysisv1.ArtifactChunk{Data: buffer[:n]}); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return status.Error(codes.Internal, readErr.Error())
		}
	}
}

func (s *Server) Health(ctx context.Context, _ *emptypb.Empty) (*analysisv1.HealthResponse, error) {
	workerCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	ready := s.service.WorkerReady(workerCtx)
	state := "ok"
	if !ready {
		state = "degraded"
	}
	return &analysisv1.HealthResponse{Status: state, WorkerReady: ready}, nil
}

func toProtoArtifact(item store.Artifact) *analysisv1.Artifact {
	return &analysisv1.Artifact{
		Id: item.ID, AnalysisId: item.AnalysisID, Kind: item.Kind, Name: item.Name,
		Sha256: item.SHA256, Size: uint64(item.Size), ContentType: item.ContentType,
	}
}

func mapError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		return status.Error(codes.NotFound, "analysis or artifact not found")
	case errors.Is(err, analysis.ErrInvalid):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, analysis.ErrQueueFull):
		return status.Error(codes.ResourceExhausted, err.Error())
	case errors.Is(err, analysis.ErrConflict):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
