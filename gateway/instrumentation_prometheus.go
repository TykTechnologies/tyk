package gateway

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/tyk/storage"
)

// PrometheusMetrics holds all Prometheus metric collectors for the Gateway
type PrometheusMetrics struct {
	// System Metrics
	goroutines  prometheus.Gauge
	memoryAlloc prometheus.Gauge
	memoryTotal prometheus.Gauge
	cpuUsage    prometheus.Gauge
	connections prometheus.Gauge

	// Gateway Metrics
	apisLoaded      prometheus.Gauge
	policiesLoaded  prometheus.Gauge
	requestsTotal   *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	requestErrors   *prometheus.CounterVec

	// Overall Gateway RED metrics (no api_id dimension)
	gatewayRequestsTotal          *prometheus.CounterVec
	gatewayRequestDuration        *prometheus.HistogramVec
	gatewayRequestUpstreamLatency *prometheus.HistogramVec
	gatewayRequestGatewayLatency  *prometheus.HistogramVec

	// Redis Metrics
	redisPoolSize    *prometheus.GaugeVec
	redisActiveConns *prometheus.GaugeVec
	redisLatency     prometheus.Histogram

	// Request Processing Metrics
	queueDepth         prometheus.Gauge
	throughput         prometheus.Gauge
	middlewareExecTime *prometheus.HistogramVec

	registry       *prometheus.Registry
	gw             *Gateway
	collectionDone chan struct{}

	// Configuration
	enablePerAPIMetrics bool

	// CPU tracking
	lastCPUTime   time.Duration
	lastCheckTime time.Time
}

// NewPrometheusMetrics creates and registers all Prometheus metrics
func NewPrometheusMetrics(gw *Gateway, prefix string, enablePerAPIMetrics bool) *PrometheusMetrics {
	registry := prometheus.NewRegistry()

	pm := &PrometheusMetrics{
		gw:                  gw,
		registry:            registry,
		collectionDone:      make(chan struct{}),
		lastCheckTime:       time.Now(),
		enablePerAPIMetrics: enablePerAPIMetrics,
	}

	// System Metrics
	pm.goroutines = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: prefix,
		Subsystem: "system",
		Name:      "goroutines",
		Help:      "Number of active goroutines",
	})

	pm.memoryAlloc = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: prefix,
		Subsystem: "system",
		Name:      "memory_alloc_bytes",
		Help:      "Bytes of allocated heap objects",
	})

	pm.memoryTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: prefix,
		Subsystem: "system",
		Name:      "memory_total_bytes",
		Help:      "Total bytes obtained from OS",
	})

	pm.cpuUsage = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: prefix,
		Subsystem: "system",
		Name:      "cpu_usage_percent",
		Help:      "CPU usage percentage",
	})

	pm.connections = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: prefix,
		Subsystem: "system",
		Name:      "open_connections",
		Help:      "Number of open connections",
	})

	// Gateway Metrics
	pm.apisLoaded = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: prefix,
		Subsystem: "gateway",
		Name:      "apis_loaded",
		Help:      "Number of APIs currently loaded",
	})

	pm.policiesLoaded = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: prefix,
		Subsystem: "gateway",
		Name:      "policies_loaded",
		Help:      "Number of policies currently loaded",
	})

	// Per-API metrics (optional, controlled by config)
	if enablePerAPIMetrics {
		pm.requestsTotal = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: prefix,
				Subsystem: "gateway",
				Name:      "requests_total",
				Help:      "Total number of requests processed per API (RED: Rate)",
			},
			[]string{"api_id", "method", "status_class"},
		)

		pm.requestDuration = prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: prefix,
				Subsystem: "gateway",
				Name:      "request_duration_seconds",
				Help:      "Request duration in seconds per API (RED: Duration)",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"api_id", "method"},
		)

		pm.requestErrors = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: prefix,
				Subsystem: "gateway",
				Name:      "request_errors_total",
				Help:      "Total number of request errors per API (RED: Errors)",
			},
			[]string{"api_id", "method", "status_class"},
		)
	}

	// Overall Gateway RED metrics (no api_id dimension)
	pm.gatewayRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: prefix,
			Subsystem: "gateway",
			Name:      "http_requests_total",
			Help:      "Total number of HTTP requests processed by the gateway (RED: Rate)",
		},
		[]string{"method", "status_class"},
	)

	pm.gatewayRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: prefix,
			Subsystem: "gateway",
			Name:      "http_request_duration_seconds",
			Help:      "Total HTTP request duration in seconds (RED: Duration)",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"method", "status_class"},
	)

	pm.gatewayRequestUpstreamLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: prefix,
			Subsystem: "gateway",
			Name:      "http_request_upstream_latency_seconds",
			Help:      "Upstream response latency in seconds (time waiting for upstream service)",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"method", "status_class"},
	)

	pm.gatewayRequestGatewayLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: prefix,
			Subsystem: "gateway",
			Name:      "http_request_gateway_latency_seconds",
			Help:      "Gateway processing latency in seconds (time spent in gateway middleware)",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"method", "status_class"},
	)

	// Redis Metrics
	pm.redisPoolSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: prefix,
			Subsystem: "redis",
			Name:      "pool_size",
			Help:      "Redis connection pool size",
		},
		[]string{"type"},
	)

	pm.redisActiveConns = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: prefix,
			Subsystem: "redis",
			Name:      "active_connections",
			Help:      "Number of active Redis connections",
		},
		[]string{"type"},
	)

	pm.redisLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: prefix,
		Subsystem: "redis",
		Name:      "operation_duration_seconds",
		Help:      "Redis operation latency in seconds",
		Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
	})

	// Request Processing Metrics
	pm.queueDepth = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: prefix,
		Subsystem: "processing",
		Name:      "queue_depth",
		Help:      "Current request queue depth",
	})

	pm.throughput = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: prefix,
		Subsystem: "processing",
		Name:      "throughput_rps",
		Help:      "Current throughput in requests per second",
	})

	pm.middlewareExecTime = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: prefix,
			Subsystem: "processing",
			Name:      "middleware_execution_seconds",
			Help:      "Middleware execution time in seconds",
			Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
		},
		[]string{"middleware_name", "api_id"},
	)

	// Register metrics
	collectors := []prometheus.Collector{
		pm.goroutines,
		pm.memoryAlloc,
		pm.memoryTotal,
		pm.cpuUsage,
		pm.connections,
		pm.apisLoaded,
		pm.policiesLoaded,
		pm.gatewayRequestsTotal,
		pm.gatewayRequestDuration,
		pm.gatewayRequestUpstreamLatency,
		pm.gatewayRequestGatewayLatency,
		pm.redisPoolSize,
		pm.redisActiveConns,
		pm.redisLatency,
		pm.queueDepth,
		pm.throughput,
		pm.middlewareExecTime,
	}

	// Conditionally add per-API metrics
	if enablePerAPIMetrics {
		collectors = append(collectors,
			pm.requestsTotal,
			pm.requestDuration,
			pm.requestErrors,
		)
	}

	registry.MustRegister(collectors...)

	return pm
}

// RegisterGoCollectors registers optional Go runtime and process collectors
func (pm *PrometheusMetrics) RegisterGoCollectors(enableGoCollector, enableProcessCollector bool) {
	if enableGoCollector {
		pm.registry.MustRegister(collectors.NewGoCollector())
		log.Debug("Registered Prometheus Go runtime collector")
	}

	if enableProcessCollector {
		pm.registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
		log.Debug("Registered Prometheus process collector")
	}
}

// UpdateSystemMetrics updates system-level metrics
func (pm *PrometheusMetrics) UpdateSystemMetrics() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	pm.goroutines.Set(float64(runtime.NumGoroutine()))
	pm.memoryAlloc.Set(float64(m.Alloc))
	pm.memoryTotal.Set(float64(m.TotalAlloc))

	// Calculate CPU usage based on GC pause times
	now := time.Now()
	elapsed := now.Sub(pm.lastCheckTime).Seconds()

	if elapsed > 0 {
		// Calculate CPU time from GC pauses
		currentCPUTime := time.Duration(m.PauseTotalNs)
		cpuDelta := currentCPUTime - pm.lastCPUTime

		// Calculate CPU usage as percentage (GC pause time / elapsed time * 100)
		// Note: This is a simplified metric showing GC CPU impact
		// For production, consider using more comprehensive CPU tracking
		cpuUsagePercent := (cpuDelta.Seconds() / elapsed) * 100.0 / float64(runtime.NumCPU())

		// Cap at 100% to handle edge cases
		if cpuUsagePercent > 100.0 {
			cpuUsagePercent = 100.0
		}

		pm.cpuUsage.Set(cpuUsagePercent)
		pm.lastCPUTime = currentCPUTime
		pm.lastCheckTime = now
	}

	if pm.gw.ConnectionWatcher != nil {
		pm.connections.Set(float64(pm.gw.ConnectionWatcher.Count()))
	}
}

// UpdateGatewayMetrics updates gateway-specific metrics
func (pm *PrometheusMetrics) UpdateGatewayMetrics() {
	pm.gw.apisMu.RLock()
	pm.apisLoaded.Set(float64(len(pm.gw.apisByID)))
	pm.gw.apisMu.RUnlock()

	pm.gw.policiesMu.RLock()
	pm.policiesLoaded.Set(float64(len(pm.gw.policiesByID)))
	pm.gw.policiesMu.RUnlock()

	// Throughput from GlobalRate
	pm.throughput.Set(float64(GlobalRate.Rate()))
}

// UpdateRedisMetrics updates Redis connection metrics
func (pm *PrometheusMetrics) UpdateRedisMetrics() {
	if pm.gw.StorageConnectionHandler != nil {
		for _, connType := range []string{storage.DefaultConn, storage.CacheConn, storage.AnalyticsConn} {
			stats := pm.gw.StorageConnectionHandler.GetRedisStats(connType)
			if stats != nil {
				labels := prometheus.Labels{"type": connType}
				pm.redisPoolSize.With(labels).Set(float64(stats.TotalConns))
				// Active connections = Total - Idle
				activeConns := stats.TotalConns - stats.IdleConns
				pm.redisActiveConns.With(labels).Set(float64(activeConns))
			}
		}
	}
}

// RecordRequest records request metrics (called from middleware/handler)
func (pm *PrometheusMetrics) RecordRequest(apiID, apiName, method string, statusCode int, totalNs, upstreamNs int64) {
	// Group status codes to reduce cardinality (2xx, 3xx, 4xx, 5xx)
	statusClass := fmt.Sprintf("%dxx", statusCode/100)

	// Convert nanoseconds to seconds for Prometheus
	totalSeconds := float64(totalNs) / 1e9
	upstreamSeconds := float64(upstreamNs) / 1e9
	gatewaySeconds := float64(totalNs-upstreamNs) / 1e9

	// Per-API metrics (only if enabled)
	if pm.enablePerAPIMetrics {
		labels := prometheus.Labels{
			"api_id":       apiID,
			"method":       method,
			"status_class": statusClass,
		}
		pm.requestsTotal.With(labels).Inc()

		durLabels := prometheus.Labels{
			"api_id": apiID,
			"method": method,
		}
		pm.requestDuration.With(durLabels).Observe(totalSeconds)

		// Record errors with status_class instead of error_type
		if statusCode >= 400 {
			errLabels := prometheus.Labels{
				"api_id":       apiID,
				"method":       method,
				"status_class": statusClass,
			}
			pm.requestErrors.With(errLabels).Inc()
		}
	}

	// Overall Gateway RED metrics (always recorded)
	gatewayLabels := prometheus.Labels{
		"method":       method,
		"status_class": statusClass,
	}
	pm.gatewayRequestsTotal.With(gatewayLabels).Inc()
	pm.gatewayRequestDuration.With(gatewayLabels).Observe(totalSeconds)
	pm.gatewayRequestUpstreamLatency.With(gatewayLabels).Observe(upstreamSeconds)
	pm.gatewayRequestGatewayLatency.With(gatewayLabels).Observe(gatewaySeconds)
}

// RecordMiddlewareExecution records middleware execution time
func (pm *PrometheusMetrics) RecordMiddlewareExecution(middlewareName, apiID string, duration float64) {
	pm.middlewareExecTime.With(prometheus.Labels{
		"middleware_name": middlewareName,
		"api_id":          apiID,
	}).Observe(duration)
}

// Handler returns the HTTP handler for metrics endpoint
func (pm *PrometheusMetrics) Handler() http.Handler {
	return promhttp.HandlerFor(pm.registry, promhttp.HandlerOpts{})
}

// StartMetricsCollection starts background metrics collection
func (pm *PrometheusMetrics) StartMetricsCollection(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)

	go func() {
		defer ticker.Stop()
		defer close(pm.collectionDone)
		for {
			select {
			case <-ctx.Done():
				log.WithFields(logrus.Fields{
					"component": "prometheus",
				}).Info("Stopping Prometheus metrics collection")
				return
			case <-ticker.C:
				pm.UpdateSystemMetrics()
				pm.UpdateGatewayMetrics()
				pm.UpdateRedisMetrics()
			}
		}
	}()
}

// WaitForShutdown waits for the metrics collection goroutine to finish
func (pm *PrometheusMetrics) WaitForShutdown() {
	if pm.collectionDone != nil {
		<-pm.collectionDone
	}
}
