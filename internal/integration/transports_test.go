package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	analysisv1 "github.com/glaslos/backstreet/gen/go/v1"
	"github.com/glaslos/backstreet/internal/analysis"
	"github.com/glaslos/backstreet/internal/blob"
	"github.com/glaslos/backstreet/internal/grpcapi"
	"github.com/glaslos/backstreet/internal/httpapi"
	"github.com/glaslos/backstreet/internal/mcpapi"
	"github.com/glaslos/backstreet/internal/store"
	"github.com/glaslos/backstreet/internal/worker"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestHTTPSubmitVisibleThroughGRPCAndMCP(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	blobs, err := blob.New(filepath.Join(root, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(root, "worker.sock")
	closeWorker := fakeWorker(t, socketPath)
	defer closeWorker()
	service := analysis.NewService(db, blobs, worker.New(socketPath), root, 1<<20, 10)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = service.Run(runCtx, 1) }()

	httpServer := httptest.NewServer(httpapi.New(service, 1<<20).Routes())
	defer httpServer.Close()
	id := submitHTTP(t, httpServer.URL)
	waitForSuccess(t, service, id)

	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	analysisv1.RegisterAnalysisServiceServer(grpcServer, grpcapi.New(service))
	go func() { _ = grpcServer.Serve(listener) }()
	defer grpcServer.Stop()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fromGRPC, err := analysisv1.NewAnalysisServiceClient(conn).GetAnalysis(ctx, &analysisv1.GetAnalysisRequest{Id: id})
	if err != nil || fromGRPC.Id != id || fromGRPC.State != analysisv1.AnalysisState_ANALYSIS_STATE_SUCCEEDED {
		t.Fatalf("gRPC result = %v, %v", fromGRPC, err)
	}

	mcpHTTP := httptest.NewServer(mcpapi.New(service, 1<<20).Handler())
	defer mcpHTTP.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: mcpHTTP.URL, DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_analysis", Arguments: map[string]any{"id": id},
	})
	if err != nil || result.IsError {
		t.Fatalf("MCP result = %v, %v", result, err)
	}
	data, _ := json.Marshal(result.StructuredContent)
	var fromMCP map[string]any
	_ = json.Unmarshal(data, &fromMCP)
	if fromMCP["id"] != id {
		t.Fatalf("MCP id = %v, want %s", fromMCP["id"], id)
	}
	if fromMCP["state"] != "ANALYSIS_STATE_SUCCEEDED" {
		t.Fatalf("MCP state = %v", fromMCP["state"])
	}
}

func submitHTTP(t *testing.T, endpoint string) string {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("options", `{"strings":true}`); err != nil {
		t.Fatal(err)
	}
	part, err := writer.CreateFormFile("sample", "fixture.exe")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("MZ benign fixture"))
	_ = writer.Close()
	request, _ := http.NewRequest(http.MethodPost, endpoint+"/v1/analyses", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("HTTP status = %d", response.StatusCode)
	}
	result := &analysisv1.Analysis{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(readAll(t, response), result); err != nil {
		t.Fatal(err)
	}
	return result.Id
}

func waitForSuccess(t *testing.T, service *analysis.Service, id string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		result, err := service.Get(context.Background(), id)
		if err == nil && result.State == analysisv1.AnalysisState_ANALYSIS_STATE_SUCCEEDED {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("analysis did not succeed")
}

func fakeWorker(t *testing.T, socketPath string) func() {
	t.Helper()
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var request map[string]any
				if json.NewDecoder(conn).Decode(&request) != nil {
					return
				}
				if request["health"] == true {
					_ = json.NewEncoder(conn).Encode(map[string]any{"status": "ok"})
					return
				}
				outputDir, _ := request["output_dir"].(string)
				_ = os.MkdirAll(outputDir, 0o750)
				reportPath := filepath.Join(outputDir, "report.json")
				_ = os.WriteFile(reportPath, []byte(`{"report_version":"5.0.0","entry_points":[]}`), 0o640)
				_ = json.NewEncoder(conn).Encode(map[string]any{
					"ok": true, "report_path": reportPath, "report_version": "5.0.0", "artifacts": []any{},
				})
			}()
		}
	}()
	return func() {
		_ = listener.Close()
		<-done
	}
}

func readAll(t *testing.T, response *http.Response) []byte {
	t.Helper()
	var data bytes.Buffer
	_, err := data.ReadFrom(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}
