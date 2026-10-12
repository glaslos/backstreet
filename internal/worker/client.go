package worker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	analysisv1 "github.com/glaslos/backstreet/gen/go/v1"
)

type Client struct {
	socket string
}

type Request struct {
	JobID      string                      `json:"job_id"`
	SamplePath string                      `json:"sample_path"`
	OutputDir  string                      `json:"output_dir"`
	Options    *analysisv1.AnalysisOptions `json:"options"`
}

type Artifact struct {
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	ContentType string `json:"content_type"`
}

type Response struct {
	OK            bool       `json:"ok"`
	ReportPath    string     `json:"report_path"`
	ReportVersion string     `json:"report_version"`
	Artifacts     []Artifact `json:"artifacts"`
	ErrorCode     string     `json:"error_code"`
	ErrorMessage  string     `json:"error_message"`
}

func New(socket string) *Client { return &Client{socket: socket} }

func (c *Client) Analyze(ctx context.Context, req Request) (Response, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.socket)
	if err != nil {
		return Response{}, fmt.Errorf("connect worker: %w", err)
	}
	defer conn.Close()
	go func() {
		<-ctx.Done()
		_ = conn.SetDeadline(time.Now())
	}()
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, fmt.Errorf("send worker request: %w", err)
	}
	var response Response
	reader := bufio.NewReaderSize(conn, 64<<10)
	if err := json.NewDecoder(reader).Decode(&response); err != nil {
		return Response{}, fmt.Errorf("read worker response: %w", err)
	}
	return response, nil
}

func (c *Client) Ready(ctx context.Context) bool {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.socket)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = json.NewEncoder(conn).Encode(map[string]bool{"health": true})
	var response map[string]any
	return json.NewDecoder(conn).Decode(&response) == nil && response["status"] == "ok"
}
