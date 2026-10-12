package metrics

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	AnalysesSubmitted = promauto.NewCounter(prometheus.CounterOpts{
		Name: "backstreet_analyses_submitted_total",
		Help: "Total analyses accepted into the queue.",
	})
	AnalysesRunning = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "backstreet_analyses_running",
		Help: "Analyses currently being emulated.",
	})
	AnalysesSucceeded = promauto.NewCounter(prometheus.CounterOpts{
		Name: "backstreet_analyses_succeeded_total",
		Help: "Total analyses that finished successfully.",
	})
	AnalysesFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "backstreet_analyses_failed_total",
		Help: "Total analyses that finished with failure.",
	})
	AnalysesCancelled = promauto.NewCounter(prometheus.CounterOpts{
		Name: "backstreet_analyses_cancelled_total",
		Help: "Total analyses cancelled by clients or workers.",
	})
)

// QueueDepthFunc returns the current queued-job count for scraping.
type QueueDepthFunc func(ctx context.Context) (int, error)

type queueCollector struct {
	desc *prometheus.Desc
	fn   QueueDepthFunc
}

// NewQueueDepthCollector builds a gauge collector backed by a live store query.
func NewQueueDepthCollector(fn QueueDepthFunc) prometheus.Collector {
	return &queueCollector{
		desc: prometheus.NewDesc(
			"backstreet_analyses_queued",
			"Analyses waiting in the queue.",
			nil,
			nil,
		),
		fn: fn,
	}
}

// RegisterQueueDepth exposes backstreet_analyses_queued on the default registry.
func RegisterQueueDepth(fn QueueDepthFunc) {
	prometheus.MustRegister(NewQueueDepthCollector(fn))
}

func (c *queueCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

func (c *queueCollector) Collect(ch chan<- prometheus.Metric) {
	depth, err := c.fn(context.Background())
	if err != nil {
		ch <- prometheus.NewInvalidMetric(c.desc, err)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, float64(depth))
}
