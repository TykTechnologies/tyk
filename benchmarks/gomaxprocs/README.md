# GOMAXPROCS Benchmark

This directory contains a docker-compose setup to benchmark and demonstrate the effect of the `GOMAXPROCS` environment variable on Tyk Gateway performance when running with CPU limits.

## Background

By default, the Go runtime sets `GOMAXPROCS` to the number of logical CPUs on the host node, not the container's CPU limit. When a container is restricted by CPU limits (e.g., 2 CPUs) but runs on a node with many cores (e.g., 16 cores), Go spawns 16 threads that constantly fight for the limited CPU quota. This leads to severe context switching, CPU throttling, and latency spikes.

Setting `GOMAXPROCS` to match the CPU limit aligns the Go scheduler with the available quota, eliminating the context switching overhead.

## Setup

The `docker-compose.yml` spins up 3 Tyk Gateway instances with different configurations, along with a Redis instance and a mock upstream service (`httpbin`):

1. `gateway-1cpu-1gmp` (Port 8081): 1 CPU limit, `GOMAXPROCS=1`
2. `gateway-2cpu-2gmp` (Port 8082): 2 CPU limit, `GOMAXPROCS=2`
3. `gateway-2cpu-unset` (Port 8083): 2 CPU limit, `GOMAXPROCS` unset

## Running the Benchmark

1. Start the environment:
   ```bash
   docker-compose up -d
   ```

2. Wait for the gateways to start and load the API. You can verify they are running by hitting the `/hello` endpoint:
   ```bash
   curl http://localhost:8081/hello
   curl http://localhost:8082/hello
   curl http://localhost:8083/hello
   ```

3. Run a load test against each gateway using a tool like [vegeta](https://github.com/tsenart/vegeta), [hey](https://github.com/rakyll/hey), or [k6](https://k6.io/).

   Example using `hey` (testing 500 concurrent workers for 30 seconds):

   **Test 1 CPU, GOMAXPROCS=1:**
   ```bash
   hey -z 30s -c 500 http://localhost:8081/test/get
   ```

   **Test 2 CPU, GOMAXPROCS=2:**
   ```bash
   hey -z 30s -c 500 http://localhost:8082/test/get
   ```

   **Test 2 CPU, GOMAXPROCS unset:**
   ```bash
   hey -z 30s -c 500 http://localhost:8083/test/get
   ```

## Expected Results

- `gateway-2cpu-2gmp` should handle significantly more throughput and have lower latency than `gateway-2cpu-unset`.
- `gateway-2cpu-unset` may experience latency spikes and early degradation due to context switching overhead.
- `gateway-1cpu-1gmp` serves as a baseline to demonstrate that a properly tuned 2 CPU pod (`gateway-2cpu-2gmp`) scales better than a 1 CPU pod.

## Cleanup

```bash
docker-compose down
```