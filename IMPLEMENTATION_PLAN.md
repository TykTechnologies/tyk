# Prometheus Metrics Integration Implementation Plan

## Overview
This document outlines the implementation plan for adding Prometheus metrics support to Tyk Gateway, following the existing patterns from StatsD and NewRelic integrations.

## Requirements (from jira.md)

### Metrics Categories
1. **System Metrics**: CPU, memory, goroutines, connections
2. **Gateway Metrics**: # APIs loaded, # Policies loaded, Requests RED metrics (Rate, Error, Duration)
3. **Redis Metrics**: pool size, active connections, latency
4. **Request Processing Metrics**: queue depth, throughput, latency, middleware execution and latency

## Architecture Analysis

### Existing Instrumentation Patterns

#### 1. StatsD Integration (`gateway/instrumentation_statsd_sink.go`)
- **Location**: `gateway/instrumentation_statsd_sink.go`
- **Sink Pattern**: Implements `health.Sink` interface
- **UDP Transport**: Uses UDP for sending metrics
- **Metrics Types**: Events, Timings, Gauges, Complete
- **Prefix Support**: Configurable prefix for all metrics
- **Buffer Management**: Batches metrics before sending

#### 2. NewRelic Integration (`internal/service/newrelic/`)
- **Location**: `internal/service/newrelic/newrelic.go`, `internal/service/newrelic/sink.go`
- **Sink Pattern**: Also implements `health.Sink` interface
- **Integration**: Uses NewRelic SDK
- **Middleware**: Router-level middleware (`nrgorilla.Middleware`)

#### 3. Current Instrumentation Hook (`gateway/instrumentation_handlers.go:21-88`)
- **Entry Point**: `setupInstrumentation()` function
- **Health Stream**: Uses `health.NewStream()` from gocraft/health
- **Monitoring**: `MonitorApplicationInstrumentation()` for GC stats and RPS
- **Activation**: Via `TYK_INSTRUMENTATION` env var or `--log-instrumentation` flag

### Key Data Points

#### Redis Pool Stats
- Connection handler: `storage/connection_handler.go`
- Redis connector interface in `storage` package
- Need to expose pool statistics from underlying Redis connection

#### System Metrics
- GC Stats: Already monitored in `MonitorApplicationInstrumentation()` (line 68-88)
- CPU/Memory: Available via `runtime` package
- Goroutines: `runtime.NumGoroutine()`
- Connections: Tracked in `ConnectionWatcher` (`internal/httputil/connection_watcher.go`)

#### Gateway Metrics
- APIs Count: `len(gw.apisByID)` in Gateway struct
- Policies Count: `len(gw.policiesByID)` in Gateway struct
- Request metrics: Already tracked via `instrument.NewJob()` calls

## Implementation Plan

### Phase 1: Configuration Structure

#### 1.1 Add Prometheus Config to `config/config.go`

**Location**: `config/config.go` (after line 1187, near StatsdPrefix)

```go
// PrometheusConfig holds configuration for Prometheus metrics exposure
type PrometheusConfig struct {
	// Enabled activates Prometheus metrics endpoint
	Enabled bool `json:"enabled"`
	// ListenAddress is the address to expose metrics (e.g., ":9090")
	ListenAddress string `json:"listen_address"`
	// Path is the HTTP path for metrics endpoint (default: "/metrics")
	Path string `json:"path"`
	// MetricPrefix is the prefix for all Tyk metrics (default: "tyk_gateway")
	MetricPrefix string `json:"metric_prefix"`
	// EnableGoCollector enables Go runtime metrics
	EnableGoCollector bool `json:"enable_go_collector"`
	// EnableProcessCollector enables process metrics
	EnableProcessCollector bool `json:"enable_process_collector"`
}

// Add to Config struct (after line 1187)
Prometheus PrometheusConfig `json:"prometheus"`
```

#### 1.2 Configuration Defaults

```go
// In config defaults
Prometheus: PrometheusConfig{
	Enabled:                false,
	ListenAddress:          ":9090",
	Path:                   "/metrics",
	MetricPrefix:           "tyk_gateway",
	EnableGoCollector:      true,
	EnableProcessCollector: true,
}
```

### Phase 2: Prometheus Metrics Registry

#### 2.1 Create Prometheus Handler (`gateway/instrumentation_prometheus.go`)

```go
package gateway

import (
	"context"
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

type PrometheusMetrics struct {
	// System Metrics
	goroutines   prometheus.Gauge
	memoryAlloc  prometheus.Gauge
	memoryTotal  prometheus.Gauge
	cpuUsage     prometheus.Gauge
	connections  prometheus.Gauge

	// Gateway Metrics
	apisLoaded      prometheus.Gauge
	policiesLoaded  prometheus.Gauge
	requestsTotal   *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	requestErrors   *prometheus.CounterVec

	// Redis Metrics
	redisPoolSize    *prometheus.GaugeVec
	redisActiveConns *prometheus.GaugeVec
	redisLatency     prometheus.Histogram

	// Request Processing Metrics
	queueDepth         prometheus.Gauge
	throughput         prometheus.Gauge
	middlewareExecTime *prometheus.HistogramVec

	registry *prometheus.Registry
	gw       *Gateway
}

func NewPrometheusMetrics(gw *Gateway, prefix string) *PrometheusMetrics {
	registry := prometheus.NewRegistry()

	pm := &PrometheusMetrics{
		gw:       gw,
		registry: registry,
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

	pm.requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: prefix,
			Subsystem: "gateway",
			Name:      "requests_total",
			Help:      "Total number of requests processed (RED: Rate)",
		},
		[]string{"api_id", "api_name", "method", "status_code"},
	)

	pm.requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: prefix,
			Subsystem: "gateway",
			Name:      "request_duration_seconds",
			Help:      "Request duration in seconds (RED: Duration)",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"api_id", "api_name", "method"},
	)

	pm.requestErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: prefix,
			Subsystem: "gateway",
			Name:      "request_errors_total",
			Help:      "Total number of request errors (RED: Errors)",
		},
		[]string{"api_id", "api_name", "method", "error_type"},
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

	// Register all metrics
	registry.MustRegister(
		pm.goroutines,
		pm.memoryAlloc,
		pm.memoryTotal,
		pm.cpuUsage,
		pm.connections,
		pm.apisLoaded,
		pm.policiesLoaded,
		pm.requestsTotal,
		pm.requestDuration,
		pm.requestErrors,
		pm.redisPoolSize,
		pm.redisActiveConns,
		pm.redisLatency,
		pm.queueDepth,
		pm.throughput,
		pm.middlewareExecTime,
	)

	return pm
}

// UpdateSystemMetrics updates system-level metrics
func (pm *PrometheusMetrics) UpdateSystemMetrics() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	pm.goroutines.Set(float64(runtime.NumGoroutine()))
	pm.memoryAlloc.Set(float64(m.Alloc))
	pm.memoryTotal.Set(float64(m.TotalAlloc))

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
				pm.redisActiveConns.With(labels).Set(float64(stats.ActiveConns))
			}
		}
	}
}

// RecordRequest records request metrics (called from middleware/handler)
func (pm *PrometheusMetrics) RecordRequest(apiID, apiName, method string, statusCode int, duration float64) {
	labels := prometheus.Labels{
		"api_id":      apiID,
		"api_name":    apiName,
		"method":      method,
		"status_code": strconv.Itoa(statusCode),
	}

	pm.requestsTotal.With(labels).Inc()

	durLabels := prometheus.Labels{
		"api_id":   apiID,
		"api_name": apiName,
		"method":   method,
	}
	pm.requestDuration.With(durLabels).Observe(duration)

	if statusCode >= 400 {
		errorType := "client_error"
		if statusCode >= 500 {
			errorType = "server_error"
		}

		errLabels := prometheus.Labels{
			"api_id":     apiID,
			"api_name":   apiName,
			"method":     method,
			"error_type": errorType,
		}
		pm.requestErrors.With(errLabels).Inc()
	}
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
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pm.UpdateSystemMetrics()
				pm.UpdateGatewayMetrics()
				pm.UpdateRedisMetrics()
			}
		}
	}()
}
```

#### 2.2 Create Prometheus Sink (`gateway/instrumentation_prometheus_sink.go`)

```go
package gateway

import (
	"github.com/gocraft/health"
)

// PrometheusSink implements health.Sink interface for Prometheus
type PrometheusSink struct {
	metrics *PrometheusMetrics
}

func NewPrometheusSink(metrics *PrometheusMetrics) *PrometheusSink {
	return &PrometheusSink{
		metrics: metrics,
	}
}

func (s *PrometheusSink) EmitEvent(job, event string, kvs map[string]string) {
	// Convert events to Prometheus metrics if needed
}

func (s *PrometheusSink) EmitEventErr(job, event string, err error, kvs map[string]string) {
	// Track errors in Prometheus
}

func (s *PrometheusSink) EmitTiming(job, event string, nanos int64, kvs map[string]string) {
	// Convert timing events to histograms
	seconds := float64(nanos) / 1e9

	if job == "MiddlewareCall" {
		if mwName, ok := kvs["mw_name"]; ok {
			apiID := kvs["api_id"]
			s.metrics.RecordMiddlewareExecution(mwName, apiID, seconds)
		}
	}
}

func (s *PrometheusSink) EmitGauge(job, event string, value float64, kvs map[string]string) {
	// Handle gauge metrics
}

func (s *PrometheusSink) EmitComplete(job string, status health.CompletionStatus, nanos int64, kvs map[string]string) {
	// Complete status tracking
}
```

### Phase 3: Gateway Integration

#### 3.1 Update `gateway/instrumentation_handlers.go`

Add Prometheus setup alongside StatsD:

```go
// Add to Gateway struct in gateway/server.go
PrometheusMetrics *PrometheusMetrics
prometheusServer  *http.Server

// Update setupInstrumentation() function
func (gw *Gateway) setupInstrumentation() {
	gwConfig := gw.GetConfig()

	// Existing StatsD setup...

	// Prometheus Setup
	if gwConfig.Prometheus.Enabled {
		log.Info("Initializing Prometheus metrics...")

		gw.PrometheusMetrics = NewPrometheusMetrics(gw, gwConfig.Prometheus.MetricPrefix)

		// Add Prometheus sink to instrument stream
		prometheusSink := NewPrometheusSink(gw.PrometheusMetrics)
		instrument.AddSink(prometheusSink)

		// Start metrics collection
		gw.PrometheusMetrics.StartMetricsCollection(gw.ctx)

		// Start Prometheus HTTP server
		gw.startPrometheusServer()

		log.WithFields(logrus.Fields{
			"listen_address": gwConfig.Prometheus.ListenAddress,
			"path":           gwConfig.Prometheus.Path,
		}).Info("Prometheus metrics endpoint started")
	}

	// Existing monitoring...
	gw.MonitorApplicationInstrumentation()
}

// Add Prometheus HTTP server
func (gw *Gateway) startPrometheusServer() {
	gwConfig := gw.GetConfig()

	mux := http.NewServeMux()
	mux.Handle(gwConfig.Prometheus.Path, gw.PrometheusMetrics.Handler())

	gw.prometheusServer = &http.Server{
		Addr:    gwConfig.Prometheus.ListenAddress,
		Handler: mux,
	}

	go func() {
		if err := gw.prometheusServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Error("Prometheus metrics server error")
		}
	}()
}

// Add shutdown logic in Gateway.gracefulShutdown()
if gw.prometheusServer != nil {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := gw.prometheusServer.Shutdown(ctx); err != nil {
		log.WithError(err).Error("Error shutting down Prometheus server")
	}
}
```

#### 3.2 Integrate Request Metrics in Success Handler

Update `gateway/handler_success.go` RecordHit function (around line 300):

```go
// Add after existing analytics recording
if gw.PrometheusMetrics != nil {
	duration := float64(latency.Total) / 1e9 // Convert nanoseconds to seconds
	gw.PrometheusMetrics.RecordRequest(
		s.Spec.APIID,
		s.Spec.Name,
		r.Method,
		code,
		duration,
	)
}
```

#### 3.3 Integrate Middleware Metrics

Update `gateway/middleware.go` createMiddleware function (around line 150-180):

```go
// Add after existing instrumentation
if gw.PrometheusMetrics != nil {
	finishTime := time.Since(startTime)
	gw.PrometheusMetrics.RecordMiddlewareExecution(
		mw.Name(),
		spec.APIID,
		float64(finishTime.Nanoseconds())/1e9,
	)
}
```

### Phase 4: Redis Metrics Enhancement

#### 4.1 Expose Redis Pool Stats

Update `storage/redis.go` to expose pool statistics:

```go
// Add method to RedisCluster
func (r *RedisCluster) PoolStats() *redis.PoolStats {
	if r.singleton != nil {
		return r.singleton.PoolStats()
	}
	return nil
}

// Add method to ConnectionHandler in storage/connection_handler.go
func (rc *ConnectionHandler) GetRedisStats(connType string) *redis.PoolStats {
	rc.connectionsMu.RLock()
	defer rc.connectionsMu.RUnlock()

	if conn, ok := rc.connections[connType]; ok {
		if redisConn, ok := conn.(*RedisCluster); ok {
			return redisConn.PoolStats()
		}
	}
	return nil
}
```

#### 4.2 Update Prometheus Metrics Collection

```go
// In PrometheusMetrics.UpdateRedisMetrics()
func (pm *PrometheusMetrics) UpdateRedisMetrics() {
	if pm.gw.StorageConnectionHandler != nil {
		for _, connType := range []string{storage.DefaultConn, storage.CacheConn, storage.AnalyticsConn} {
			stats := pm.gw.StorageConnectionHandler.GetRedisStats(connType)
			if stats != nil {
				pm.redisPoolSize.WithLabelValues(connType).Set(float64(stats.TotalConns))
				pm.redisActiveConns.WithLabelValues(connType).Set(float64(stats.ActiveConns))
			}
		}
	}
}
```

### Phase 5: Documentation and Configuration

#### 5.1 Configuration Example

Add to `tyk.conf.example`:

```json
{
  "prometheus": {
    "enabled": true,
    "listen_address": ":9090",
    "path": "/metrics",
    "metric_prefix": "tyk_gateway",
    "enable_go_collector": true,
    "enable_process_collector": true
  }
}
```

#### 5.2 Environment Variables

Support environment variable configuration:
- `TYK_GW_PROMETHEUS_ENABLED`
- `TYK_GW_PROMETHEUS_LISTENADDRESS`
- `TYK_GW_PROMETHEUS_PATH`
- `TYK_GW_PROMETHEUS_METRICPREFIX`

### Phase 6: Testing

#### 6.1 Unit Tests

Create `gateway/instrumentation_prometheus_test.go`:

```go
package gateway

import (
	"testing"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestPrometheusMetrics(t *testing.T) {
	// Test metric registration
	// Test metric updates
	// Test HTTP handler
}

func TestPrometheusSink(t *testing.T) {
	// Test sink integration with health.Stream
}
```

#### 6.2 Integration Tests

- Test metrics endpoint accessibility
- Verify metric values match expected gateway state
- Test with high request load
- Verify graceful shutdown

### Phase 7: Additional Enhancements

#### 7.1 Optional Go Runtime Collectors

```go
// In NewPrometheusMetrics, optionally register Go collectors
if gwConfig.Prometheus.EnableGoCollector {
	registry.MustRegister(prometheus.NewGoCollector())
}

if gwConfig.Prometheus.EnableProcessCollector {
	registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
}
```

#### 7.2 Custom Labels Support

Add configuration for custom labels:

```go
type PrometheusConfig struct {
	// ... existing fields ...
	CustomLabels map[string]string `json:"custom_labels"`
}
```

## Implementation Timeline

### Week 1: Foundation
- [ ] Day 1-2: Configuration structure (Phase 1)
- [ ] Day 3-5: Prometheus metrics registry and handler (Phase 2.1, 2.2)

### Week 2: Integration
- [ ] Day 1-2: Gateway integration (Phase 3.1, 3.2)
- [ ] Day 3-4: Middleware integration (Phase 3.3)
- [ ] Day 5: Redis metrics enhancement (Phase 4)

### Week 3: Testing and Documentation
- [ ] Day 1-2: Unit tests (Phase 6.1)
- [ ] Day 3-4: Integration tests (Phase 6.2)
- [ ] Day 5: Documentation and examples (Phase 5)

### Week 4: Enhancements and Review
- [ ] Day 1-2: Additional enhancements (Phase 7)
- [ ] Day 3-4: Code review and refinements
- [ ] Day 5: Final testing and deployment preparation

## Metrics Exposed (Summary)

### System Metrics
- `tyk_gateway_system_goroutines` - Number of active goroutines
- `tyk_gateway_system_memory_alloc_bytes` - Allocated heap memory
- `tyk_gateway_system_memory_total_bytes` - Total memory from OS
- `tyk_gateway_system_cpu_usage_percent` - CPU usage
- `tyk_gateway_system_open_connections` - Open connections

### Gateway Metrics
- `tyk_gateway_gateway_apis_loaded` - Number of loaded APIs
- `tyk_gateway_gateway_policies_loaded` - Number of loaded policies
- `tyk_gateway_gateway_requests_total{api_id, api_name, method, status_code}` - Total requests (RED: Rate)
- `tyk_gateway_gateway_request_duration_seconds{api_id, api_name, method}` - Request duration histogram (RED: Duration)
- `tyk_gateway_gateway_request_errors_total{api_id, api_name, method, error_type}` - Request errors (RED: Errors)

### Redis Metrics
- `tyk_gateway_redis_pool_size{type}` - Connection pool size (types: default, cache, analytics)
- `tyk_gateway_redis_active_connections{type}` - Active connections (types: default, cache, analytics)
- `tyk_gateway_redis_operation_duration_seconds` - Operation latency histogram

### Request Processing Metrics
- `tyk_gateway_processing_queue_depth` - Request queue depth
- `tyk_gateway_processing_throughput_rps` - Throughput in RPS
- `tyk_gateway_processing_middleware_execution_seconds{middleware_name, api_id}` - Middleware execution time

## Migration and Compatibility

- Prometheus metrics run independently alongside existing StatsD/NewRelic
- No breaking changes to existing instrumentation
- Can be enabled/disabled via configuration
- Uses separate HTTP server to avoid conflicts with main gateway ports

## Security Considerations

1. **Separate Metrics Port**: Run Prometheus endpoint on dedicated port
2. **Access Control**: Document firewall rules for metrics port
3. **Sensitive Data**: Ensure no API keys or sensitive data in labels
4. **Rate Limiting**: Consider adding rate limiting to metrics endpoint for production

## Deployment Recommendations

1. **Production**: Enable with dedicated metrics port (e.g., 9090)
2. **Kubernetes**: Use ServiceMonitor for automatic discovery
3. **Docker**: Expose metrics port in container configuration
4. **Monitoring**: Set up Prometheus scraping with 15-30s interval

## References

- Existing implementations:
  - `gateway/instrumentation_statsd_sink.go`
  - `internal/service/newrelic/`
  - `gateway/instrumentation_handlers.go`
- Prometheus client library: `github.com/prometheus/client_golang`
- Health stream: `github.com/gocraft/health`
