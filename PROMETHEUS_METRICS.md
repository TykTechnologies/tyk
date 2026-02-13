# Prometheus Metrics Integration for Tyk Gateway

This document describes the Prometheus metrics integration for Tyk Gateway, providing comprehensive monitoring and observability capabilities.

## Table of Contents

- [Overview](#overview)
- [Configuration](#configuration)
- [Environment Variables](#environment-variables)
- [Available Metrics](#available-metrics)
- [Usage Examples](#usage-examples)
- [Integration with Monitoring Systems](#integration-with-monitoring-systems)
- [Best Practices](#best-practices)

## Overview

Tyk Gateway now supports native Prometheus metrics export through a dedicated HTTP endpoint. This integration provides detailed metrics across four key categories:

1. **System Metrics**: Runtime performance and resource utilization
2. **Gateway Metrics**: API and policy management, request processing (RED metrics)
3. **Redis Metrics**: Connection pool statistics and performance
4. **Request Processing Metrics**: Queue depth, throughput, and middleware performance

## Configuration

### Configuration File

Add the following section to your `tyk.conf`:

```json
{
  "prometheus": {
    "enabled": true,
    "listen_address": ":9090",
    "path": "/metrics",
    "metric_prefix": "tyk_gateway",
    "enable_go_collector": true,
    "enable_process_collector": true,
    "enable_per_api_metrics": false
  }
}
```

### Configuration Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable/disable Prometheus metrics endpoint |
| `listen_address` | string | `":9090"` | Address and port for metrics endpoint |
| `path` | string | `"/metrics"` | HTTP path for metrics endpoint |
| `metric_prefix` | string | `"tyk_gateway"` | Prefix for all Tyk metrics |
| `enable_go_collector` | boolean | `true` | Enable Go runtime metrics collection |
| `enable_process_collector` | boolean | `true` | Enable process-level metrics collection |
| `enable_per_api_metrics` | boolean | `false` | Enable per-API metrics with `api_id` label (increases cardinality) |

## Environment Variables

All configuration options can be set via environment variables using the `TYK_GW_PROMETHEUS_` prefix:

```bash
export TYK_GW_PROMETHEUS_ENABLED=true
export TYK_GW_PROMETHEUS_LISTENADDRESS=":9090"
export TYK_GW_PROMETHEUS_PATH="/metrics"
export TYK_GW_PROMETHEUS_METRICPREFIX="tyk_gateway"
export TYK_GW_PROMETHEUS_ENABLEGOCOLLECTOR=true
export TYK_GW_PROMETHEUS_ENABLEPROCESSCOLLECTOR=true
export TYK_GW_PROMETHEUS_ENABLEPERAPIMETRICS=false
```

## Available Metrics

### System Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `tyk_gateway_system_goroutines` | Gauge | Number of active goroutines | - |
| `tyk_gateway_system_memory_alloc_bytes` | Gauge | Bytes of allocated heap objects | - |
| `tyk_gateway_system_memory_total_bytes` | Gauge | Total bytes obtained from OS | - |
| `tyk_gateway_system_cpu_usage_percent` | Gauge | CPU usage percentage | - |
| `tyk_gateway_system_open_connections` | Gauge | Number of open connections | - |

### Gateway Metrics (RED)

#### Overall Gateway Metrics (Always Available)

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `tyk_gateway_gateway_apis_loaded` | Gauge | Number of APIs currently loaded | - |
| `tyk_gateway_gateway_policies_loaded` | Gauge | Number of policies currently loaded | - |
| `tyk_gateway_gateway_http_requests_total` | Counter | Total HTTP requests across all APIs (RED: Rate) | `method`, `status_class` |
| `tyk_gateway_gateway_http_request_duration_seconds` | Histogram | Total HTTP request duration across all APIs (RED: Duration) | `method`, `status_class` |
| `tyk_gateway_gateway_http_request_upstream_latency_seconds` | Histogram | Upstream service latency (time waiting for upstream response) | `method`, `status_class` |
| `tyk_gateway_gateway_http_request_gateway_latency_seconds` | Histogram | Gateway processing latency (time spent in gateway middleware) | `method`, `status_class` |

**Note**: `status_class` groups status codes as `2xx`, `3xx`, `4xx`, `5xx` to reduce cardinality.

**Latency Breakdown**:
- **Total Duration** = Upstream Latency + Gateway Latency
- **Upstream Latency**: Time waiting for the upstream service to respond
- **Gateway Latency**: Time spent in Tyk gateway processing (authentication, rate limiting, transformations, etc.)

**Error Metrics**: Calculate errors from `status_class=~"4xx|5xx"` in the requests metrics above.

#### Per-API Metrics (Optional - `enable_per_api_metrics: true`)

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `tyk_gateway_gateway_requests_total` | Counter | Total requests per API (RED: Rate) | `api_id`, `method`, `status_class` |
| `tyk_gateway_gateway_request_duration_seconds` | Histogram | Request duration per API (RED: Duration) | `api_id`, `method` |
| `tyk_gateway_gateway_request_errors_total` | Counter | Request errors per API (RED: Errors) | `api_id`, `method`, `status_class` |

**Warning**: Per-API metrics can create high cardinality with many APIs. Enable only when needed for detailed per-API monitoring.

### Redis Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `tyk_gateway_redis_pool_size` | Gauge | Redis connection pool size | `type` (default, cache, analytics) |
| `tyk_gateway_redis_active_connections` | Gauge | Active Redis connections | `type` (default, cache, analytics) |
| `tyk_gateway_redis_operation_duration_seconds` | Histogram | Redis operation latency | - |

### Request Processing Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `tyk_gateway_processing_queue_depth` | Gauge | Current request queue depth | - |
| `tyk_gateway_processing_throughput_rps` | Gauge | Throughput in requests per second | - |
| `tyk_gateway_processing_middleware_execution_seconds` | Histogram | Middleware execution time | `middleware_name`, `api_id` |

## Usage Examples

### Basic Curl Test

```bash
curl http://localhost:9090/metrics
```

### Sample Prometheus Configuration

Add this to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'tyk-gateway'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 15s
    scrape_timeout: 10s
```

### Example Metrics Output

```promql
# System Metrics
tyk_gateway_system_goroutines 245
tyk_gateway_system_memory_alloc_bytes 45678912
tyk_gateway_system_open_connections 12

# Gateway Metrics (Overall - Always Available)
tyk_gateway_gateway_apis_loaded 5
tyk_gateway_gateway_policies_loaded 3
tyk_gateway_gateway_http_requests_total{method="GET",status_class="2xx"} 1523
tyk_gateway_gateway_http_requests_total{method="POST",status_class="4xx"} 12
tyk_gateway_gateway_http_request_duration_seconds_bucket{method="GET",status_class="2xx",le="0.1"} 1450
tyk_gateway_gateway_http_request_upstream_latency_seconds_bucket{method="GET",status_class="2xx",le="0.05"} 1400
tyk_gateway_gateway_http_request_gateway_latency_seconds_bucket{method="GET",status_class="2xx",le="0.005"} 1500

# Gateway Metrics (Per-API - Only if enable_per_api_metrics=true)
tyk_gateway_gateway_requests_total{api_id="api1",method="GET",status_class="2xx"} 1000
tyk_gateway_gateway_request_errors_total{api_id="api1",method="GET",status_class="4xx"} 5

# Redis Metrics
tyk_gateway_redis_pool_size{type="default"} 100
tyk_gateway_redis_active_connections{type="default"} 45
```

## Integration with Monitoring Systems

### Grafana Dashboard

Create a Grafana dashboard using these example queries:

**Overall Request Rate (RED: Rate)**
```promql
sum(rate(tyk_gateway_gateway_http_requests_total[5m])) by (method, status_class)
```

**Overall Request Duration P95 (RED: Duration)**
```promql
histogram_quantile(0.95, sum(rate(tyk_gateway_gateway_http_request_duration_seconds_bucket[5m])) by (le, method))
```

**Overall Error Rate (RED: Errors)**
```promql
sum(rate(tyk_gateway_gateway_http_requests_total{status_class=~"4xx|5xx"}[5m])) by (status_class)
```

**Upstream Latency P95**
```promql
histogram_quantile(0.95, sum(rate(tyk_gateway_gateway_http_request_upstream_latency_seconds_bucket[5m])) by (le, method))
```

**Gateway Processing Latency P95**
```promql
histogram_quantile(0.95, sum(rate(tyk_gateway_gateway_http_request_gateway_latency_seconds_bucket[5m])) by (le, method))
```

**Latency Breakdown Comparison**
```promql
# Compare upstream vs gateway latency
sum(rate(tyk_gateway_gateway_http_request_upstream_latency_seconds_sum[5m])) / sum(rate(tyk_gateway_gateway_http_request_upstream_latency_seconds_count[5m]))
/
sum(rate(tyk_gateway_gateway_http_request_gateway_latency_seconds_sum[5m])) / sum(rate(tyk_gateway_gateway_http_request_gateway_latency_seconds_count[5m]))
```

**Per-API Request Rate (if `enable_per_api_metrics=true`)**
```promql
sum(rate(tyk_gateway_gateway_requests_total[5m])) by (api_id, method, status_class)
```

**Per-API Error Rate (if `enable_per_api_metrics=true`)**
```promql
sum(rate(tyk_gateway_gateway_request_errors_total[5m])) by (api_id, status_class)
```

**Redis Pool Utilization**
```promql
(tyk_gateway_redis_active_connections / tyk_gateway_redis_pool_size) * 100
```

### Kubernetes ServiceMonitor

For automatic Prometheus discovery in Kubernetes:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: tyk-gateway
spec:
  selector:
    matchLabels:
      app: tyk-gateway
  endpoints:
  - port: prometheus
    interval: 15s
    path: /metrics
```

### Docker Compose

```yaml
version: '3.8'
services:
  tyk-gateway:
    image: tykio/tyk-gateway:latest
    ports:
      - "8080:8080"
      - "9090:9090"
    environment:
      - TYK_GW_PROMETHEUS_ENABLED=true
      - TYK_GW_PROMETHEUS_LISTENADDRESS=:9090

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9091:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
```

## Latency Analysis

### Using Latency Breakdown

The gateway provides detailed latency breakdown to help identify performance bottlenecks:

**Identify Bottlenecks**:
```promql
# If upstream latency is high, the problem is in your backend services
histogram_quantile(0.95, rate(tyk_gateway_gateway_http_request_upstream_latency_seconds_bucket[5m]))

# If gateway latency is high, the problem is in gateway middleware/processing
histogram_quantile(0.95, rate(tyk_gateway_gateway_http_request_gateway_latency_seconds_bucket[5m]))
```

**Calculate Overhead Percentage**:
```promql
# What percentage of total time is spent in the gateway?
(
  sum(rate(tyk_gateway_gateway_http_request_gateway_latency_seconds_sum[5m]))
  /
  sum(rate(tyk_gateway_gateway_http_request_duration_seconds_sum[5m]))
) * 100
```

**Common Patterns**:
- **High Upstream, Low Gateway**: Backend services are slow - optimize your APIs
- **Low Upstream, High Gateway**: Gateway processing is slow - review middleware, rate limits, plugins
- **Both High**: Multiple bottlenecks - prioritize based on which contributes more to total latency

### Troubleshooting Scenarios

**Scenario 1: Slow Response Times**
1. Check total P95: `histogram_quantile(0.95, rate(tyk_gateway_gateway_http_request_duration_seconds_bucket[5m]))`
2. Compare upstream vs gateway latency to identify where time is spent
3. If upstream is slow: Review backend service performance
4. If gateway is slow: Review middleware configuration, plugins, rate limiting

**Scenario 2: Increased Latency After Deployment**
```promql
# Compare gateway latency before and after deployment
histogram_quantile(0.95,
  sum(rate(tyk_gateway_gateway_http_request_gateway_latency_seconds_bucket[5m] offset 1h)) by (le)
)
```

**Scenario 3: Inconsistent Performance**
```promql
# High variance in latency
stddev_over_time(
  histogram_quantile(0.95,
    rate(tyk_gateway_gateway_http_request_duration_seconds_bucket[5m])
  )[10m:1m]
)
```

## Best Practices

### Cardinality Management

**Understanding Per-API Metrics**:
- Per-API metrics add the `api_id` label to metrics
- With 100 APIs × 5 methods × 5 status classes = 2,500 time series per metric
- High cardinality can impact Prometheus performance and storage

**When to Enable Per-API Metrics**:
- ✅ **Development/Testing**: Detailed debugging and analysis
- ✅ **Small Deployments**: <50 APIs with low request volume
- ✅ **Specific Monitoring**: Temporary troubleshooting of specific APIs
- ❌ **Large Deployments**: >100 APIs or high request volume
- ❌ **Production (default)**: Use overall gateway metrics instead

**Recommended Configuration**:
```json
{
  "prometheus": {
    "enabled": true,
    "enable_per_api_metrics": false,  // Default: use overall metrics
    "enable_go_collector": true,
    "enable_process_collector": true
  }
}
```

**Alternative Approaches**:
- Use overall gateway metrics (`gateway_http_requests_total`) for alerting
- Enable per-API metrics temporarily for debugging specific issues
- Use API analytics/logging for detailed per-API investigation

### Performance Considerations

1. **Scrape Interval**: Use 15-30 second intervals for production
2. **Metrics Port**: Run on a separate port (9090) from the gateway (8080)
3. **Network Security**: Restrict metrics endpoint access via firewall rules
4. **Cardinality**: Keep per-API metrics disabled unless specifically needed

### Security Recommendations

1. **Separate Network**: Expose metrics port only on internal network
2. **Authentication**: Use network-level authentication (VPN, IP whitelisting)
3. **Sensitive Data**: Metrics do not include API keys or sensitive request data

### Troubleshooting

**Issue**: Metrics endpoint not accessible
```bash
# Check if Prometheus is enabled in configuration
grep -A 5 "prometheus" /opt/tyk-gateway/tyk.conf

# Check if metrics port is listening
netstat -tln | grep 9090
```

**Issue**: No data in metrics
- Ensure gateway is receiving traffic
- Check gateway logs for Prometheus initialization messages
- Verify metrics collection goroutine is running

**Issue**: High memory usage in Prometheus
- Check cardinality: `curl -s http://localhost:9090/api/v1/status/tsdb | jq`
- **If per-API metrics are enabled**: Disable `enable_per_api_metrics` to reduce cardinality
- Reduce scrape frequency from 15s to 30s or 60s
- Consider disabling `enable_go_collector` and `enable_process_collector` if not needed
- Use recording rules to pre-aggregate high-cardinality metrics

**Issue**: Too many time series
- Verify per-API metrics setting: `grep enable_per_api_metrics /opt/tyk-gateway/tyk.conf`
- Calculate expected cardinality: `(number of APIs) × (methods) × (status classes)`
- Consider using overall gateway metrics instead of per-API metrics
- Use Prometheus relabeling to drop unnecessary labels

### Alerting Rules

Example Prometheus alerting rules:

```yaml
groups:
  - name: tyk_gateway
    rules:
      - alert: TykHighErrorRate
        expr: |
          sum(rate(tyk_gateway_gateway_http_requests_total{status_class=~"4xx|5xx"}[5m]))
          /
          sum(rate(tyk_gateway_gateway_http_requests_total[5m]))
          > 0.05
        for: 5m
        annotations:
          summary: "High error rate detected (>5%)"
          description: "Gateway error rate is {{ $value | humanizePercentage }}"

      - alert: TykHighP95Latency
        expr: |
          histogram_quantile(0.95,
            sum(rate(tyk_gateway_gateway_http_request_duration_seconds_bucket[5m])) by (le)
          ) > 1
        for: 5m
        annotations:
          summary: "High P95 latency detected"
          description: "P95 latency is {{ $value }}s (threshold: 1s)"

      - alert: TykRedisPoolExhaustion
        expr: |
          (tyk_gateway_redis_active_connections / tyk_gateway_redis_pool_size) > 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Redis connection pool nearly exhausted"
          description: "Redis pool utilization is {{ $value | humanizePercentage }} for {{ $labels.type }}"

      - alert: TykHighMemoryUsage
        expr: tyk_gateway_system_memory_alloc_bytes > 1e9
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage detected"
          description: "Memory usage is {{ $value | humanize1024 }}"
```

## Migration from StatsD

Prometheus can run alongside existing StatsD instrumentation without conflicts. Both systems collect metrics independently and can be gradually migrated:

1. Enable Prometheus alongside StatsD
2. Validate metrics accuracy in Prometheus
3. Update monitoring dashboards to use Prometheus
4. Disable StatsD once migration is complete

## Support

For issues, feature requests, or questions:
- GitHub Issues: https://github.com/TykTechnologies/tyk/issues
- Documentation: https://tyk.io/docs
- Community Forum: https://community.tyk.io
