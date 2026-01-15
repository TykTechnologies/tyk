# Certificate Expiry Monitoring - Test Cases & Scenarios

This document defines test cases and scenarios for validating the certificate expiry monitoring implementation.

## Table of Contents

- [Unit Tests](#unit-tests)
- [Integration Tests](#integration-tests)
- [Performance Tests](#performance-tests)
- [Manual Test Scenarios](#manual-test-scenarios)
- [Edge Case Testing](#edge-case-testing)
- [Security Testing](#security-testing)
- [Observability Testing](#observability-testing)
- [Test Execution Summary](#test-execution-summary)

---

## Unit Tests

### Cooldown Cache Tests (`internal/certcheck/cooldown_test.go`)

**TC-U-001: In-Memory Cache - Set and Get**
- Setup: Create in-memory cache
- Action: Set cooldown for cert ID  
- Expected: Get returns true before TTL, false after TTL
- Verify: Cache hit/miss behavior

**TC-U-002: Redis Cache Fallback**
- Setup: Mock Redis that returns error
- Action: Attempt to set cooldown
- Expected: Error logged, operation continues
- Verify: Graceful degradation

**TC-U-003: Dual Cache Hierarchy**
- Setup: Both caches available
- Action: Check cooldown
- Expected: In-memory checked first, Redis not called if hit
- Verify: Cache hierarchy works correctly

### Certificate Info Extraction Tests

**TC-U-004: Extract Valid Certificate Info**
- Setup: Generate valid certificate
- Action: Call extractCertInfo
- Expected: Returns cert_id, common_name, not_after, until_expiry
- Verify: All fields populated correctly

**TC-U-005: Extract from Nil Certificate**
- Setup: Nil certificate pointer
- Action: Call extractCertInfo
- Expected: Returns (empty, false), no panic
- Verify: Graceful handling

**TC-U-006: Certificate ID Uniqueness**
- Setup: Generate 1000 unique certificates
- Action: Extract cert IDs
- Expected: All 1000 cert IDs are unique  
- Verify: SHA256 hash provides uniqueness

### Expiry Check Logic Tests

**TC-U-007: Certificate Expiring Soon Detection**
- Setup: Cert expires in 15 days, threshold = 30 days
- Action: Check if expiring soon
- Expected: Returns true, days_remaining = 15
- Verify: Calculation correct

**TC-U-008: Certificate Already Expired**
- Setup: Cert expired 5 days ago
- Action: Check expiry status
- Expected: Returns expired, days_since_expiry = 5
- Verify: Negative time handled correctly

**TC-U-009: Certificate Not Yet Expiring**
- Setup: Cert expires in 60 days, threshold = 30 days
- Action: Check if expiring soon
- Expected: Returns false, no event fires
- Verify: Threshold respected

**TC-U-010: Certificate Expiry Threshold Boundary**
- Setup: Cert expires in exactly 30 days, threshold = 30
- Action: Check if expiring soon
- Expected: Returns true, days_remaining = 30
- Verify: Boundary condition (>=, not >)

### Batch Processing Tests

**TC-U-011: Add Certificate to Batch**
- Setup: Create batcher
- Action: Add certificate
- Expected: Certificate stored in batch
- Verify: Batch size increments

**TC-U-012: Batch Auto-Flush on Timer**
- Setup: Batcher with 1-second flush interval
- Action: Add cert, wait 1.5 seconds
- Expected: Batch flushed automatically
- Verify: Timer-based flushing works

**TC-U-013: Batch Duplicate Deduplication**
- Setup: Batcher
- Action: Add same cert ID twice
- Expected: Deduplicated (only one entry)
- Verify: Map-based deduplication works

**TC-U-014: Empty Batch Flush**
- Setup: Batcher with no certificates
- Action: Call Flush()
- Expected: No errors, no events fired
- Verify: Handles empty batch gracefully

### Event Generation Tests

**TC-U-015: Generate CertificateExpiringSoon Event**
- Setup: Cert expiring in 10 days
- Action: Generate event payload
- Expected: Correct event type, message, all fields populated
- Verify: Event structure matches schema

**TC-U-016: Event Fields for Each Role**
- Setup: Certs for server, ca, client, upstream
- Action: Generate events for each
- Expected: cert_role field correct for each (server/ca/client/upstream)
- Verify: Role tagging works

---

## Integration Tests

### End-to-End Certificate Monitoring

**TC-I-001: Server Certificate Monitoring Full Flow**
```
Setup:
  - Start gateway with test config
  - Configure server cert expiring in 3 days
  - Set warning_threshold_days=30
  - Configure test webhook endpoint

Action:
  - Trigger periodic check

Expected:
  - Event fired: CertificateExpiringSoon
  - Webhook received with cert_role="server"
  - Redis cooldown key created

Verify:
  - Event payload correct
  - Webhook delivery successful
  - Logs show check occurred
```

**TC-I-002: Client Certificate on mTLS Request**
```
Setup:
  - API with use_mutual_tls_auth=true
  - Client cert expiring in 5 days
  - Webhook configured

Action:
  - Make API request with client cert

Expected:
  - Certificate checked during request
  - Event fired with cert_role="client"
  - Webhook contains api_id

Verify:
  - Request succeeds
  - Event metadata correct (api_id, cert_role)
```

**TC-I-003: Upstream Certificate Periodic Monitoring**
```
Setup:
  - API with upstream_certificates configured
  - Cert expiring in 10 days
  - Periodic checking enabled

Action:
  - Wait for periodic upstream check

Expected:
  - Upstream cert checked every check_interval_seconds
  - Event fired with cert_role="upstream"
  - Includes api_id

Verify:
  - Periodic checking works without API traffic
```

**TC-I-004: CA Certificate Monitoring**
```
Setup:
  - Global CA cert configured (security.certificates.api)
  - API uses CA for client verification
  - CA cert expiring in 7 days

Action:
  - Periodic check runs

Expected:
  - CA cert checked by GlobalCertificateMonitor
  - Event fired with cert_role="ca"
  - No api_id (global cert)

Verify:
  - CA certs monitored separately
```

### Cooldown Behavior

**TC-I-005: Check Cooldown Prevents Duplicate Checks**
```
Setup: check_cooldown_seconds=60
Action:
  - Check cert at T=0
  - Attempt check at T=30
Expected:
  - First check succeeds
  - Second check skipped (cooldown active)
  - Log: "Skipping certificate - cooldown active"
Verify: Redis key exists with ~30s TTL
```

**TC-I-006: Event Cooldown Separate from Check Cooldown**
```
Setup:
  - check_cooldown_seconds=10
  - event_cooldown_seconds=60

Action:
  - Check at T=0 (event fires)
  - Check at T=15 (check happens)
  - Check at T=30 (check happens)

Expected:
  - Only one event at T=0
  - Checks at T=15, T=30 run but no events

Verify:
  - Separate cooldowns work correctly
```

**TC-I-007: Cooldown Expiry Allows New Events**
```
Setup: event_cooldown_seconds=20
Action:
  - Fire event at T=0
  - Wait 25 seconds
  - Check again
Expected:
  - Events fire at both T=0 and T=25
Verify: Cooldown expires correctly
```

### Redis Integration

**TC-I-008: Redis Connection on Startup**
- Setup: Redis running
- Action: Gateway starts
- Expected: Redis connection established, no errors
- Verify: PING succeeds, key prefix configured

**TC-I-009: Redis Unavailable on Startup**
- Setup: Redis not running
- Action: Gateway starts
- Expected: Gateway starts successfully, warning logged, in-memory cache used
- Verify: Graceful degradation

**TC-I-010: Redis Disconnect During Operation**
- Setup: Gateway running with Redis
- Action: Stop Redis, trigger cert check
- Expected: Check continues with in-memory cache, error logged, events still fire
- Verify: Resilient to Redis failures

### Webhook Delivery

**TC-I-011: Successful Webhook Delivery**
- Setup: Mock webhook server responding 200 OK
- Action: Event fires
- Expected: POST request sent with JSON body, all fields present
- Verify: Request format correct, headers set

**TC-I-012: Webhook Delivery Failure (5xx)**
- Setup: Mock webhook returns 500
- Action: Event fires
- Expected: Error logged, monitoring continues
- Verify: Failure doesn't block monitoring

**TC-I-013: Multiple Webhooks per Event**
- Setup: Configure 3 webhook handlers for CertificateExpiringSoon
- Action: Event fires
- Expected: All 3 webhooks receive event
- Verify: Array of handlers supported

### Lifecycle

**TC-I-014: Gateway Startup Certificate Check**
- Setup: Gateway stopped, certs expiring
- Action: Start gateway
- Expected: Periodic checks start, first check happens
- Verify: Monitoring begins on startup

**TC-I-015: Gateway Shutdown Cleanup**
- Setup: Gateway running, monitoring active
- Action: Graceful shutdown
- Expected: Background goroutines stop, context cancelled, no leaks
- Verify: Clean shutdown, WaitGroup completes

---

## Performance Tests

### Load Tests

**TC-P-001: 1,000 Certificates Periodic Check**
```
Setup: 1,000 certificates, check_interval_seconds=60
Action: Trigger periodic check
Expected:
  - All 1,000 certs checked within <5 seconds
  - Memory usage stable
  - CPU usage <50%
Measure:
  - Check duration
  - Memory delta
  - CPU usage
```

**TC-P-002: 10,000 Certificates Periodic Check**
```
Setup: 10,000 certificates
Action: Periodic check
Expected:
  - Completes within check_interval
  - Memory < 500MB increase
  - Gateway remains responsive
Measure:
  - Time to complete
  - Peak memory
  - Request latency during check
```

**TC-P-003: Concurrent Client Certificate Checks**
```
Setup: 100 concurrent requests, each with different client cert
Action: Send 100 requests simultaneously
Expected:
  - All requests succeed
  - P95 latency < 100ms increase
Measure:
  - Request latency distribution
  - Throughput impact
```

**TC-P-004: Goroutine Count with Many APIs**
```
Setup: 500 APIs with upstream certs
Action: Start gateway, monitor goroutines
Expected:
  - Goroutine count stable
  - No leaks
  - Count < 2 × APIs
Measure:
  - Goroutine count over time
```

**TC-P-005: Memory Usage Over 24 Hours**
```
Setup: 1,000 certs, monitoring running
Action: Run for 24 hours
Expected:
  - Memory stable
  - No memory leak
  - GC running normally
Measure:
  - Heap size over time
  - GC frequency
```

---

## Manual Test Scenarios

### Scenario 1: Fresh Installation

```
Objective: Verify monitoring works on new installation

Steps:
1. Install gateway (no existing config)
2. Add certificate_expiry_monitor config
3. Configure test cert (expires in 3 days)
4. Configure webhook to webhook.site
5. Start gateway
6. Wait for periodic check

Expected:
✓ Monitoring initializes without errors
✓ Webhook received within check_interval_seconds
✓ cert_role field present and correct
✓ No errors in logs
✓ Redis keys created

Pass Criteria:
- Webhook received successfully
- Event structure valid
- All logs clean
```

### Scenario 2: All Certificate Roles

```
Objective: Verify all 4 roles monitored

Steps:
1. Configure server cert (expires 5 days)
2. Configure CA cert (expires 10 days)
3. Configure API with client certs (expires 15 days)
4. Configure API with upstream certs (expires 20 days)
5. Start gateway
6. Make mTLS request
7. Wait for periodic checks

Expected:
✓ 4 events fired (one per role)
✓ cert_role correct: server, ca, client, upstream
✓ Server/CA: no api_id
✓ Client/upstream: has api_id

Pass Criteria:
- All 4 webhooks received
- Role fields correct
- api_id presence correct
```

### Scenario 3: Cooldown Verification

```
Objective: Verify cooldowns work as configured

Setup:
- check_cooldown_seconds=30
- event_cooldown_seconds=60
- Cert expires in 5 days

Steps:
1. FLUSHALL Redis
2. Trigger check at T=0
3. Wait 35 seconds
4. FLUSHALL Redis
5. Trigger check at T=35
6. Wait 35 seconds (T=70 total)
7. FLUSHALL Redis
8. Trigger check

Expected:
✓ T=0: Event fires
✓ T=35: No event (cooldown active)
✓ T=70: Event fires (cooldown expired)

Pass Criteria:
- 2 events total
- Logs show cooldown skip at T=35
- Redis keys have correct TTLs
```

### Scenario 4: Redis Failure Recovery

```
Objective: Verify resilience to Redis failures

Steps:
1. Start gateway with Redis
2. Configure monitoring
3. Trigger check (creates cooldown)
4. Verify cooldown in Redis
5. Stop Redis
6. Trigger check
7. Start Redis
8. Trigger check

Expected:
✓ Pre-stop: Cooldowns work
✓ During outage: In-memory works, events fire
✓ Post-restart: Redis resumes

Pass Criteria:
- No gateway crash
- Events during outage
- Warning logs
- Auto-recovery
```

---

## Edge Case Testing

### Certificate Edge Cases

**TC-E-001: Certificate Expires Today (Day 0)**
- Cert NotAfter = today at 23:59:59
- Expected: days_remaining=0, event fires

**TC-E-002: Certificate Expired Today (Day 0)**
- Cert NotAfter = today at 00:00:01
- Expected: days_since_expiry=0, expired event fires

**TC-E-003: Very Long Expiry (10 years)**
- Expected: No event, check succeeds, no overflow

**TC-E-004: Far Past Expiry (1000 days ago)**
- Expected: Expired event, days_since_expiry=1000

**TC-E-005: Empty Common Name**
- CN = ""
- Expected: cert_name="", event fires normally

**TC-E-006: Special Characters in CN**
- CN = "*.example.com" or "example.com/test"
- Expected: Preserved, JSON escaped properly

### Configuration Edge Cases

**TC-E-007: Zero warning_threshold_days**
- Set warning_threshold_days=0
- Expected: Events only for expired certs

**TC-E-008: check_interval_seconds=0**
- Disable periodic checking
- Expected: No periodic checks, only on-demand

**TC-E-009: event_cooldown < check_cooldown**
- event=10s, check=60s
- Expected: Works (suboptimal), maybe warn

### Concurrency Edge Cases

**TC-E-010: Simultaneous Batch Adds**
- 10 goroutines adding same cert
- Expected: No race, cert appears once

**TC-E-011: Flush During Add**
- Add cert while batch flushing
- Expected: Cert added to next batch, no loss

---

## Security Testing

### Input Validation

**TC-S-001: Malicious CN (XSS)**
- CN = "<script>alert('xss')</script>"
- Expected: String stored as-is, JSON escaped
- Verify: No XSS in webhook receivers

**TC-S-002: SQL Injection in CN**
- CN = "'; DROP TABLE certs; --"
- Expected: Harmless (not used in SQL)

**TC-S-003: Control Characters in CN**
- CN contains null bytes
- Expected: Sanitized/escaped, JSON valid

### Webhook Security

**TC-S-004: Webhook to Internal IP**
- Configure http://127.0.0.1:6379
- Expected: Request sent (no SSRF protection currently)
- Verify: Document security concern

**TC-S-005: HTTP vs HTTPS Webhooks**
- Expected: Both work, HTTPS recommended
- Verify: Document best practice

---

## Observability Testing

### Logging

**TC-O-001: Debug Logs - Periodic Check**
- log_level=debug, trigger check
- Expected: "Running periodic certificate check" logged

**TC-O-002: Warning Logs - Certificate Issue**
- Invalid certificate file
- Expected: Warning with cert details

**TC-O-003: Error Logs - Redis Failure**
- Redis unavailable
- Expected: Error with connection details

---

## Test Execution Summary

### Priority P0 (Must Pass for Production)

Unit Tests:
- TC-U-001 through TC-U-016

Integration Tests:
- TC-I-001 through TC-I-007 (E2E + Cooldowns)
- TC-I-008 through TC-I-010 (Redis)
- TC-I-011, TC-I-012 (Webhooks)
- TC-I-014, TC-I-015 (Lifecycle)

Performance Tests:
- TC-P-001 through TC-P-003 (Load)

Manual Scenarios:
- Scenarios 1-4

### Priority P1 (Should Pass Soon)

Performance Tests:
- TC-P-004, TC-P-005 (Stress, long-running)

Edge Cases:
- TC-E-001 through TC-E-011

Security Tests:
- TC-S-001 through TC-S-005

Observability:
- TC-O-001 through TC-O-003

### Acceptance Criteria

For production readiness:

- [ ] All P0 tests passing
- [ ] Code coverage > 80%
- [ ] All manual scenarios verified
- [ ] Performance benchmarks met
- [ ] Security tests completed
- [ ] Documentation complete
- [ ] No P0/P1 bugs open

### Test Environment

**Infrastructure:**
- Docker / Docker Compose
- Redis 6.x+
- Mock webhook server
- OpenSSL for cert generation

**Test Data:**
- 10 short-lived certs (3-30 days)
- 5 expired certs
- 1000 certs for load testing (script-generated)

**Tools:**
- Prometheus (metrics validation)
- Redis CLI (cooldown verification)
- curl (webhook testing)

---

## Test Utilities

### Generate Short-Lived Certificates

```bash
#!/bin/bash
# generate-test-certs.sh

# Server cert (3 days)
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout test-server-key.pem \
  -out test-server-cert.pem \
  -days 3 -subj "/CN=test-server"

# CA cert (5 days)
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout test-ca-key.pem \
  -out test-ca-cert.pem \
  -days 5 -subj "/CN=Test CA"

# Upstream cert (10 days)
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout test-upstream-key.pem \
  -out test-upstream-cert.pem \
  -days 10 -subj "/CN=Upstream Service"

# Combine cert + key for upstream
cat test-upstream-cert.pem test-upstream-key.pem > test-upstream-combined.pem
```

### Mock Webhook Server

```python
#!/usr/bin/env python3
# mock_webhook.py

from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class MockWebhook(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        body = self.rfile.read(length)
        
        print(f"\nWebhook received: {self.path}")
        print(f"Body: {body.decode()}")
        
        # Return different statuses based on path
        if 'error' in self.path:
            self.send_response(500)
        elif 'timeout' in self.path:
            import time
            time.sleep(15)  # Cause timeout
        else:
            self.send_response(200)
        
        self.end_headers()

if __name__ == '__main__':
    HTTPServer(('0.0.0.0', 8888), MockWebhook).serve_forever()
```
