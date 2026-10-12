package metrics_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/glaslos/backstreet/internal/metrics"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestAnalysisCounters(t *testing.T) {
	before := testutil.ToFloat64(metrics.AnalysesSubmitted)
	metrics.AnalysesSubmitted.Inc()
	if got := testutil.ToFloat64(metrics.AnalysesSubmitted); got != before+1 {
		t.Fatalf("AnalysesSubmitted = %v, want %v", got, before+1)
	}
}

func TestQueueDepthCollector(t *testing.T) {
	reg := prometheus.NewRegistry()
	if err := reg.Register(metrics.NewQueueDepthCollector(func(context.Context) (int, error) {
		return 7, nil
	})); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "backstreet_analyses_queued 7") {
		t.Fatalf("metrics body missing queued gauge:\n%s", text)
	}
}
