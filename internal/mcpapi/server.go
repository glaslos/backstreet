package mcpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	analysisv1 "github.com/glaslos/backstreet/gen/go/v1"
	"github.com/glaslos/backstreet/internal/analysis"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type Server struct {
	service   *analysis.Service
	maxUpload int64
	server    *mcp.Server
}

type SubmitInput struct {
	Filename       string            `json:"filename" jsonschema:"name of the submitted sample"`
	SampleBase64   string            `json:"sample_base64" jsonschema:"base64-encoded PE, driver, or shellcode"`
	IdempotencyKey string            `json:"idempotency_key,omitempty"`
	Kind           string            `json:"kind,omitempty" jsonschema:"pe or shellcode"`
	Architecture   string            `json:"architecture,omitempty" jsonschema:"x86 or x64; required for shellcode"`
	TimeoutSeconds uint32            `json:"timeout_seconds,omitempty"`
	AllEntrypoints bool              `json:"all_entrypoints,omitempty"`
	Strings        bool              `json:"strings,omitempty"`
	Coverage       bool              `json:"coverage,omitempty"`
	MemoryTracing  bool              `json:"memory_tracing,omitempty"`
	Environment    map[string]string `json:"environment,omitempty"`
	DNSNames       map[string]string `json:"dns_names,omitempty"`
}

type IDInput struct {
	ID string `json:"id"`
}

func New(service *analysis.Service, maxUpload int64) *Server {
	s := &Server{service: service, maxUpload: maxUpload}
	s.server = mcp.NewServer(&mcp.Implementation{
		Name: "backstreet", Title: "Backstreet Speakeasy API", Version: "0.1.0",
	}, &mcp.ServerOptions{
		Instructions: "Submit Windows samples for asynchronous Speakeasy emulation, then inspect status, reports, and artifacts.",
	})
	mcp.AddTool(s.server, &mcp.Tool{Name: "submit_analysis", Description: "Submit a base64-encoded sample for asynchronous analysis."}, s.submit)
	mcp.AddTool(s.server, &mcp.Tool{Name: "get_analysis", Description: "Get analysis status and metadata."}, s.get)
	mcp.AddTool(s.server, &mcp.Tool{Name: "cancel_analysis", Description: "Cancel a queued or running analysis."}, s.cancel)
	mcp.AddTool(s.server, &mcp.Tool{Name: "get_report", Description: "Get the completed Speakeasy JSON report."}, s.report)
	mcp.AddTool(s.server, &mcp.Tool{Name: "list_artifacts", Description: "List report and dropped-file resources for an analysis."}, s.artifacts)
	s.server.AddResourceTemplate(&mcp.ResourceTemplate{
		Name: "analysis-report", Description: "Speakeasy JSON report", MIMEType: "application/json",
		URITemplate: "backstreet://analyses/{id}/report",
	}, s.readResource)
	s.server.AddResourceTemplate(&mcp.ResourceTemplate{
		Name: "analysis-artifact", Description: "Analysis output artifact",
		URITemplate: "backstreet://analyses/{id}/artifacts/{artifact_id}",
	}, s.readResource)
	return s
}

func (s *Server) Handler() http.Handler {
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s.server }, nil)
}

func (s *Server) submit(ctx context.Context, _ *mcp.CallToolRequest, input SubmitInput) (*mcp.CallToolResult, any, error) {
	if int64(len(input.SampleBase64)) > (s.maxUpload*4/3)+4 {
		return nil, nil, fmt.Errorf("sample exceeds configured upload limit")
	}
	data, err := base64.StdEncoding.DecodeString(input.SampleBase64)
	if err != nil {
		return nil, nil, fmt.Errorf("sample_base64 is invalid: %w", err)
	}
	options := &analysisv1.AnalysisOptions{
		Kind: analysisv1.SampleKind_SAMPLE_KIND_PE, TimeoutSeconds: input.TimeoutSeconds,
		AllEntrypoints: input.AllEntrypoints, Strings: input.Strings, Coverage: input.Coverage,
		MemoryTracing: input.MemoryTracing, Environment: input.Environment, DnsNames: input.DNSNames,
	}
	if strings.EqualFold(input.Kind, "shellcode") {
		options.Kind = analysisv1.SampleKind_SAMPLE_KIND_SHELLCODE
	}
	switch strings.ToLower(input.Architecture) {
	case "x86":
		options.Architecture = analysisv1.Architecture_ARCHITECTURE_X86
	case "x64", "amd64":
		options.Architecture = analysisv1.Architecture_ARCHITECTURE_X64
	}
	result, err := s.service.Submit(ctx, input.Filename, input.IdempotencyKey, options, bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}
	return nil, protoMap(result), nil
}

func (s *Server) get(ctx context.Context, _ *mcp.CallToolRequest, input IDInput) (*mcp.CallToolResult, any, error) {
	result, err := s.service.Get(ctx, input.ID)
	if err != nil {
		return nil, nil, err
	}
	return nil, protoMap(result), nil
}

func (s *Server) cancel(ctx context.Context, _ *mcp.CallToolRequest, input IDInput) (*mcp.CallToolResult, any, error) {
	result, err := s.service.Cancel(ctx, input.ID)
	if err != nil {
		return nil, nil, err
	}
	return nil, protoMap(result), nil
}

func (s *Server) report(ctx context.Context, _ *mcp.CallToolRequest, input IDInput) (*mcp.CallToolResult, any, error) {
	result, err := s.service.Report(ctx, input.ID)
	if err != nil {
		return nil, nil, err
	}
	return nil, protoMap(result), nil
}

func (s *Server) artifacts(ctx context.Context, _ *mcp.CallToolRequest, input IDInput) (*mcp.CallToolResult, any, error) {
	items, err := s.service.Artifacts(ctx, input.ID)
	if err != nil {
		return nil, nil, err
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		out = append(out, map[string]any{
			"id": item.ID, "kind": item.Kind, "name": item.Name, "sha256": item.SHA256,
			"size": item.Size, "content_type": item.ContentType,
			"uri": fmt.Sprintf("backstreet://analyses/%s/artifacts/%s", input.ID, item.ID),
		})
	}
	return nil, map[string]any{"artifacts": out}, nil
}

func (s *Server) readResource(ctx context.Context, request *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	parsed, err := url.Parse(request.Params.URI)
	if err != nil || parsed.Scheme != "backstreet" || parsed.Host != "analyses" {
		return nil, fmt.Errorf("invalid Backstreet resource URI")
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) == 2 && parts[1] == "report" {
		report, err := s.service.Report(ctx, parts[0])
		if err != nil {
			return nil, err
		}
		data, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(report)
		if err != nil {
			return nil, err
		}
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
			URI: request.Params.URI, MIMEType: "application/json", Text: string(data),
		}}}, nil
	}
	if len(parts) == 3 && parts[1] == "artifacts" {
		item, reader, err := s.service.Artifact(ctx, parts[0], parts[2])
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		data, err := io.ReadAll(io.LimitReader(reader, s.maxUpload+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > s.maxUpload {
			return nil, fmt.Errorf("artifact is too large for MCP; use HTTP or gRPC download")
		}
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
			URI: request.Params.URI, MIMEType: item.ContentType, Blob: data,
		}}}, nil
	}
	return nil, fmt.Errorf("resource not found")
}

func protoMap(message proto.Message) map[string]any {
	data, _ := protojson.MarshalOptions{UseProtoNames: true}.Marshal(message)
	var result map[string]any
	_ = json.Unmarshal(data, &result)
	return result
}
