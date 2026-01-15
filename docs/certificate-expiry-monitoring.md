# Certificate Expiry Monitoring

## Overview

Tyk Gateway includes comprehensive certificate expiry monitoring that proactively checks and reports on certificates before they expire. The system monitors four types of certificates:

- **Server certificates**: TLS certificates used by the gateway to serve HTTPS traffic
- **CA certificates**: Certificate Authority certificates used to verify client certificates
- **Client certificates**: Certificates presented by clients for mutual TLS authentication
- **Upstream certificates**: Certificates used when connecting to upstream services

The monitoring system fires webhook events when certificates are approaching expiration or have expired, allowing operators to take proactive action.

## Architecture

### Components

1. **GlobalCertificateMonitor**: Monitors gateway-level server and CA certificates
2. **CertificateCheckMW**: Middleware that monitors API-specific client and upstream certificates
3. **CertificateExpiryCheckBatcher**: Background processor that batches certificate checks and fires events
4. **Event System**: Webhook delivery system that sends notifications to configured endpoints

### Monitoring Flow

```
Certificate Discovery → Batch Processing → Expiry Check → Event Firing → Webhook Delivery
```

1. **Discovery**: Certificates are discovered from configuration and checked during:
   - Periodic intervals (configurable)
   - Request processing (for client certificates)
   - TLS handshakes

2. **Batch Processing**: Discovered certificates are batched to reduce event spam and improve performance

3. **Expiry Check**: Each batch is processed to check certificate expiry against configured thresholds

4. **Event Firing**: Events are fired with cooldown periods to prevent duplicate notifications

5. **Webhook Delivery**: Events are delivered to configured webhook endpoints

## Configuration

### Gateway Configuration

Add the following to your `tyk.conf`:

```json
{
  "security": {
    "certificate_expiry_monitor": {
      "warning_threshold_days": 30,
      "check_cooldown_seconds": 10,
      "event_cooldown_seconds": 20,
      "check_interval_seconds": 30
    }
  },
  "event_handlers": {
    "events": {
      "CertificateExpiringSoon": [
        {
          "handler_name": "eh_web_hook_handler",
          "handler_meta": {
            "method": "POST",
            "target_path": "https://your-webhook-endpoint.com/certificates",
            "header_map": {
              "Content-Type": "application/json",
              "X-Event-Type": "CertificateExpiringSoon"
            },
            "event_timeout": 10
          }
        }
      ],
      "CertificateExpired": [
        {
          "handler_name": "eh_web_hook_handler",
          "handler_meta": {
            "method": "POST",
            "target_path": "https://your-webhook-endpoint.com/certificates",
            "header_map": {
              "Content-Type": "application/json",
              "X-Event-Type": "CertificateExpired"
            },
            "event_timeout": 10
          }
        }
      ]
    }
  }
}
```

### Configuration Parameters

#### certificate_expiry_monitor

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `warning_threshold_days` | int | 30 | Number of days before expiry to start firing warnings |
| `check_cooldown_seconds` | int | 86400 | Minimum time between checking the same certificate |
| `event_cooldown_seconds` | int | 86400 | Minimum time between firing events for the same certificate |
| `check_interval_seconds` | int | 3600 | Interval for periodic certificate checks (0 disables periodic checking) |

**Important**:
- `check_cooldown_seconds`: Controls how often a certificate is checked for expiry
- `event_cooldown_seconds`: Controls how often events are fired for the same certificate (even if it's checked more frequently)
- `check_interval_seconds`: Controls the periodic background check interval

**Recommended Settings**:

Development/Testing:
```json
{
  "warning_threshold_days": 30,
  "check_cooldown_seconds": 10,
  "event_cooldown_seconds": 20,
  "check_interval_seconds": 30
}
```

Production:
```json
{
  "warning_threshold_days": 30,
  "check_cooldown_seconds": 86400,
  "event_cooldown_seconds": 86400,
  "check_interval_seconds": 3600
}
```

## Certificate Roles

Each certificate is tagged with a role that indicates its purpose:

| Role | Description | Monitoring Source |
|------|-------------|-------------------|
| `server` | TLS certificates for HTTPS endpoints | GlobalCertificateMonitor |
| `ca` | Certificate Authority certificates for client verification | GlobalCertificateMonitor |
| `client` | Client certificates for mutual TLS | CertificateCheckMW |
| `upstream` | Certificates for upstream service connections | CertificateCheckMW |

The `cert_role` field in webhook payloads identifies which type of certificate triggered the event.

## Event Payloads

### CertificateExpiringSoon Event

Fired when a certificate is within the warning threshold period.

```json
{
  "event": "CertificateExpiringSoon",
  "message": "Certificate localhost is expiring in 2 days and 5 hours",
  "cert_id": "8c31605b3c8b...",
  "cert_name": "localhost",
  "expires_at": "2026-01-17T13:51:52Z",
  "days_remaining": 2,
  "cert_role": "server",
  "api_id": "test-api-id",
  "timestamp": "2026-01-14T17:43:05Z"
}
```

### CertificateExpired Event

Fired when a certificate has already expired.

```json
{
  "event": "CertificateExpired",
  "message": "Certificate localhost expired 3 days ago",
  "cert_id": "8c31605b3c8b...",
  "cert_name": "localhost",
  "expired_at": "2026-01-10T13:51:52Z",
  "days_since_expiry": 3,
  "cert_role": "server",
  "api_id": "test-api-id",
  "timestamp": "2026-01-14T17:43:05Z"
}
```

### Payload Fields

| Field | Type | Description |
|-------|------|-------------|
| `event` | string | Event type: `CertificateExpiringSoon` or `CertificateExpired` |
| `message` | string | Human-readable description |
| `cert_id` | string | SHA256 hash of certificate |
| `cert_name` | string | Common Name (CN) from certificate |
| `expires_at` | string (RFC3339) | When certificate expires (ExpiringSoon event) |
| `expired_at` | string (RFC3339) | When certificate expired (Expired event) |
| `days_remaining` | int | Days until expiry (ExpiringSoon event) |
| `days_since_expiry` | int | Days since expiry (Expired event) |
| `cert_role` | string | Certificate role: `server`, `ca`, `client`, or `upstream` |
| `api_id` | string | API ID (only for API-specific certificates) |
| `timestamp` | string (RFC3339) | When event was fired |

## Testing

### Prerequisites

1. Tyk Gateway with certificate expiry monitoring enabled
2. Test certificates (can generate short-lived certs for testing)
3. Webhook endpoint (use [webhook.site](https://webhook.site) for quick testing)

### Generating Test Certificates

Generate certificates with short expiry for testing:

```bash
# Server certificate (expires in 3 days)
openssl req -x509 -newkey rsa:2048 -keyout test-server-key.pem \
  -out test-server-cert.pem -days 3 -nodes \
  -subj "/CN=localhost"

# Client CA certificate (expires in 3 days)
openssl req -x509 -newkey rsa:2048 -keyout test-ca-key.pem \
  -out test-ca-cert.pem -days 3 -nodes \
  -subj "/CN=Test CA"

# Upstream certificate (expires in 3 days)
openssl req -x509 -newkey rsa:2048 -keyout test-upstream-key.pem \
  -out test-upstream-cert.pem -days 3 -nodes \
  -subj "/CN=Upstream Service"
```

### Test Configuration

1. **Configure short thresholds** (for faster testing):

```json
{
  "security": {
    "certificate_expiry_monitor": {
      "warning_threshold_days": 30,
      "check_cooldown_seconds": 10,
      "event_cooldown_seconds": 20,
      "check_interval_seconds": 30
    }
  }
}
```

2. **Configure webhook endpoint**:

```json
{
  "event_handlers": {
    "events": {
      "CertificateExpiringSoon": [
        {
          "handler_name": "eh_web_hook_handler",
          "handler_meta": {
            "method": "POST",
            "target_path": "https://webhook.site/YOUR-UNIQUE-ID",
            "header_map": {
              "Content-Type": "application/json",
              "X-Event-Type": "CertificateExpiringSoon"
            },
            "event_timeout": 10
          }
        }
      ]
    }
  }
}
```

3. **Configure certificates in gateway**:

```json
{
  "http_server_options": {
    "use_ssl": true,
    "ssl_insecure_skip_verify": true,
    "certificates": [
      {
        "domain_name": "*",
        "cert_file": "certs/test-server-cert.pem",
        "key_file": "certs/test-server-key.pem"
      }
    ]
  },
  "security": {
    "certificates": {
      "api": ["certs/test-ca-cert.pem"],
      "upstream": {
        "*": "certs/test-upstream-combined.pem"
      }
    }
  }
}
```

### Test Procedures

Each certificate role requires specific setup and testing procedures. Follow these detailed steps to test each role independently.

#### Test 1: Server Certificate Monitoring

**What it tests**: Gateway server TLS certificates (role: `server`)

**Setup Steps**:

1. Generate a short-lived server certificate:
```bash
cd /path/to/tyk-certs
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout gateway/certs/test-server-key.pem \
  -out gateway/certs/test-server-cert.pem \
  -days 3 -subj "/CN=localhost"
```

2. Configure gateway to use the certificate in `tyk.conf`:
```json
{
  "http_server_options": {
    "use_ssl": true,
    "ssl_insecure_skip_verify": true,
    "certificates": [
      {
        "domain_name": "*",
        "cert_file": "certs/test-server-cert.pem",
        "key_file": "certs/test-server-key.pem"
      }
    ]
  }
}
```

3. Restart gateway:
```bash
docker compose restart tyk-gateway
```

**Test Steps**:

1. Monitor logs for periodic check:
```bash
docker compose logs -f tyk-gateway | grep -E "(periodic certificate check|GlobalCertificateMonitor)"
```

2. Wait for first periodic check (30 seconds with test config)

3. Verify server certificate event fired:
```bash
docker compose logs tyk-gateway | grep -E "EXPIRY EVENT.*localhost.*server"
```

Expected output:
```
level=debug msg="EXPIRY EVENT FIRED for certificate 'localhost' - expires in 68 hours"
  cert_id=8c31605b component=GlobalCertificateMonitor event_type=CertificateExpiringSoon
```

4. Check webhook payload has `"cert_role": "server"`

5. Verify Redis cooldown created:
```bash
docker exec tyk-redis redis-cli KEYS "cert-cooldown:*8c31605b*"
```

**Expected Results**:
- ✅ Event fired with `cert_role: "server"`
- ✅ Certificate identified by CommonName "localhost"
- ✅ No `api_id` in payload (global certificate)
- ✅ Monitored by GlobalCertificateMonitor

---

#### Test 2: CA Certificate Monitoring

**What it tests**: Certificate Authority certificates for client verification (role: `ca`)

**Setup Steps**:

1. Generate a short-lived CA certificate:
```bash
cd /path/to/certs/directory
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout test-ca-key.pem \
  -out test-ca-cert.pem \
  -days 3 -subj "/CN=Test CA"
```

2. Configure gateway to use CA certificate in `tyk.conf`:
```json
{
  "security": {
    "certificates": {
      "api": ["certs/test-ca-cert.pem"]
    }
  }
}
```

3. Configure API to use mutual TLS in API definition (`apps/test-mtls-api.json`):
```json
{
  "api_id": "test-mtls-api",
  "name": "Test mTLS API",
  "slug": "test-mtls",
  "listen_path": "/test-mtls/",
  "target_url": "http://httpbin.org/",
  "use_mutual_tls_auth": true,
  "client_certificates": []
}
```

**Note**: When `client_certificates` is empty, the gateway uses the global CA certificates from `security.certificates.api`.

4. Restart gateway:
```bash
docker compose restart tyk-gateway
```

**Test Steps**:

1. Monitor logs for periodic check:
```bash
docker compose logs -f tyk-gateway | grep -E "Test CA|CheckAPICertificates"
```

2. Wait for periodic check (30 seconds)

3. Verify CA certificate event fired:
```bash
docker compose logs tyk-gateway | grep -E "EXPIRY EVENT.*Test CA"
```

Expected output:
```
level=debug msg="EXPIRY EVENT FIRED for certificate 'Test CA' - expires in 68 hours"
  cert_id=b833da6b component=GlobalCertificateMonitor event_type=CertificateExpiringSoon
```

4. Check webhook payload has `"cert_role": "ca"`

**Expected Results**:
- ✅ Event fired with `cert_role: "ca"`
- ✅ Certificate identified by CommonName "Test CA"
- ✅ No `api_id` in payload (global CA certificate)
- ✅ Monitored by GlobalCertificateMonitor

---

#### Test 3: Client Certificate Monitoring

**What it tests**: Client certificates presented for mutual TLS (role: `client`)

**Setup Steps**:

1. Use the CA certificate from Test 2, or generate a new one

2. Generate a client certificate signed by the CA:
```bash
cd /path/to/certs/directory

# Generate client private key
openssl genrsa -out client-key.pem 2048

# Generate CSR
openssl req -new -key client-key.pem \
  -out client-csr.pem \
  -subj "/CN=Test Client"

# Sign with CA (expires in 3 days)
openssl x509 -req -in client-csr.pem \
  -CA test-ca-cert.pem \
  -CAkey test-ca-key.pem \
  -CAcreateserial -out client-cert.pem \
  -days 3
```

3. Ensure API is configured for mutual TLS (from Test 2)

4. Ensure CA certificate is configured in `tyk.conf` (from Test 2)

**Test Steps**:

1. Make request with client certificate to trigger check:
```bash
curl -k --cert /path/to/certs/client-cert.pem \
  --key /path/to/certs/client-key.pem \
  https://localhost:8080/test-mtls/get
```

2. Monitor logs for certificate check:
```bash
docker compose logs tyk-gateway | grep -E "CertificateCheckMW|Batch certificates"
```

Expected output:
```
level=debug msg="Batch certificates for expiration check with 1 certificates"
  api_id=test-mtls-api api_name="Test mTLS API" mw=CertificateCheckMW
```

3. Wait for batch flush (default 5 seconds)

4. Verify client certificate event fired:
```bash
docker compose logs tyk-gateway | grep -E "EXPIRY EVENT.*Test CA.*client"
```

5. Check webhook payload:
   - Has `"cert_role": "client"`
   - Has `"api_id": "test-mtls-api"`

**Expected Results**:
- ✅ Event fired with `cert_role: "client"`
- ✅ Includes `api_id` (API-specific certificate)
- ✅ Triggered by request (not just periodic check)
- ✅ Monitored by CertificateCheckMW

**Note**: Client certificates are checked during request processing AND periodic checks.

---

#### Test 4: Upstream Certificate Monitoring

**What it tests**: Certificates used for upstream mTLS connections (role: `upstream`)

**Setup Steps**:

1. Generate a short-lived upstream certificate (with private key):
```bash
cd /path/to/certs/directory
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout test-upstream-key.pem \
  -out test-upstream-cert.pem \
  -days 3 -subj "/CN=Upstream Service"

# Create combined certificate file (cert + key)
cat test-upstream-cert.pem test-upstream-key.pem > test-upstream-combined.pem
```

2. Configure API to use upstream certificate (`apps/test-upstream-api.json`):
```json
{
  "api_id": "test-upstream-api",
  "name": "Test Upstream API",
  "slug": "test-upstream",
  "listen_path": "/test-upstream/",
  "target_url": "https://httpbin.org/",
  "upstream_certificates": {
    "*": "certs/test-upstream-combined.pem"
  }
}
```

**Note**: The `upstream_certificates` field maps domain patterns to certificate file paths. Use `"*"` to apply the certificate to all upstream connections.

3. Restart gateway:
```bash
docker compose restart tyk-gateway
```

**Test Steps**:

1. Monitor logs for upstream certificate check:
```bash
docker compose logs -f tyk-gateway | grep -E "Upstream Service|upstream.*certif"
```

2. Wait for periodic check (30 seconds)

3. Verify periodic checking started:
```bash
docker compose logs tyk-gateway | grep -E "Starting periodic upstream certificate checking"
```

Expected output:
```
level=info msg="Starting periodic upstream certificate checking"
  api_id=test-upstream-api api_name="Test Upstream API"
  interval_seconds=30 mw=CertificateCheckMW
```

4. Wait for certificate check to execute

5. Verify upstream certificate event fired:
```bash
docker compose logs tyk-gateway | grep -E "EXPIRY EVENT.*Upstream Service"
```

Expected output:
```
level=debug msg="EXPIRY EVENT FIRED for certificate 'Upstream Service' - expires in 69 hours"
  api_id=test-upstream-api api_name="Test Upstream API"
  cert_id=d76058d8 event_type=CertificateExpiringSoon
```

6. Check webhook payload:
   - Has `"cert_role": "upstream"`
   - Has `"api_id": "test-upstream-api"`

**Expected Results**:
- ✅ Event fired with `cert_role: "upstream"`
- ✅ Includes `api_id` (API-specific certificate)
- ✅ Checked periodically (not triggered by requests)
- ✅ Monitored by CertificateCheckMW

---

#### Test 5: Cooldown Behavior

**What it tests**: Event cooldown mechanism prevents duplicate events

**Setup Steps**:

1. Use any of the certificates from Tests 1-4
2. Ensure Redis is running and connected
3. Configure with short cooldowns for testing:
```json
{
  "security": {
    "certificate_expiry_monitor": {
      "check_cooldown_seconds": 10,
      "event_cooldown_seconds": 20
    }
  }
}
```

**Test Steps**:

1. **First Event**: Flush Redis to clear all cooldowns:
```bash
docker exec tyk-redis redis-cli FLUSHALL
```

2. Wait 35 seconds for periodic check

3. Verify event fired:
```bash
docker compose logs --tail=50 tyk-gateway | grep "EXPIRY EVENT FIRED"
```

4. Note the certificate ID from the log output

5. **Test Check Cooldown**: Flush Redis again immediately:
```bash
docker exec tyk-redis redis-cli FLUSHALL
```

6. Verify NO new check happens (check cooldown active):
```bash
# Should see "Skipping certificate - cooldown active"
docker compose logs --tail=20 tyk-gateway | grep -i cooldown
```

7. **Test Event Cooldown**: Wait 15 seconds (longer than check cooldown, shorter than event cooldown)

8. Flush Redis again:
```bash
docker exec tyk-redis redis-cli FLUSHALL
```

9. Verify certificate IS checked but NO event fired (event cooldown still active):
```bash
docker compose logs --tail=50 tyk-gateway | grep -E "Flush certificate.*batch_size=[1-9]"
# Should see batch processed but no "EXPIRY EVENT FIRED"
```

10. **Cooldown Expires**: Wait 25+ seconds total (event cooldown expires)

11. Flush Redis one more time:
```bash
docker exec tyk-redis redis-cli FLUSHALL
```

12. Verify NEW event fires:
```bash
docker compose logs --tail=50 tyk-gateway | grep "EXPIRY EVENT FIRED"
```

**Expected Results**:
- ✅ First flush: Event fires immediately
- ✅ Second flush (< 10s): No check, no event (check cooldown)
- ✅ Third flush (< 20s): Certificate checked, no event (event cooldown)
- ✅ Fourth flush (> 20s): Certificate checked, event fires
- ✅ Redis cooldown keys created: `cert-cooldown:check:CERT_ID` and `cert-cooldown:event:CERT_ID`

---

#### Test 6: All Roles Together

**What it tests**: Multiple certificate roles monitored simultaneously

**Setup Steps**:

1. Configure all certificates from Tests 1-4
2. Ensure all APIs are loaded
3. Set test configuration with short intervals

**Test Steps**:

1. Flush Redis:
```bash
docker exec tyk-redis redis-cli FLUSHALL
```

2. Monitor logs for all certificate types:
```bash
docker compose logs -f tyk-gateway | grep -E "EXPIRY EVENT|cert_role"
```

3. Wait for periodic check (30 seconds)

4. Count events fired:
```bash
docker compose logs tyk-gateway | grep "EXPIRY EVENT FIRED" | wc -l
```

5. Verify webhook payloads received with different roles:
```bash
# Check your webhook endpoint for payloads with:
# - "cert_role": "server"
# - "cert_role": "ca"
# - "cert_role": "client" (if request made)
# - "cert_role": "upstream"
```

6. Verify distinct certificate IDs:
```bash
docker compose logs tyk-gateway | grep "EXPIRY EVENT" | \
  grep -o "cert_id=[a-f0-9]*" | sort -u
```

**Expected Results**:
- ✅ Multiple events fired (at least server, ca, upstream)
- ✅ Each event has correct `cert_role`
- ✅ Server/CA certificates have no `api_id`
- ✅ Client/upstream certificates have `api_id`
- ✅ All events delivered to webhook endpoint

### Verification

Check the following to verify monitoring is working:

1. **Log Messages**:
```bash
# Periodic checks running
grep "periodic certificate check" logs

# Certificates being checked
grep "Checked.*certificates for expiry" logs

# Events being fired
grep "EXPIRY EVENT FIRED" logs

# Webhooks being delivered
grep "FIRING HANDLER" logs
```

2. **Redis Keys** (cooldowns):
```bash
docker exec tyk-redis redis-cli KEYS "cert-cooldown:*"
```

3. **Webhook Delivery**:
- Check webhook endpoint for received payloads
- Verify `cert_role` field is present
- Verify timestamps are recent

## Troubleshooting

### No Events Firing

**Symptoms**: Gateway running but no certificate events fired

**Checks**:
1. Verify certificates are within warning threshold:
   ```bash
   openssl x509 -in cert.pem -noout -enddate
   ```

2. Check if monitoring is enabled:
   ```bash
   grep "certificate_expiry_monitor" tyk.conf
   ```

3. Verify periodic checks are running:
   ```bash
   docker compose logs tyk-gateway | grep "periodic certificate check"
   ```

4. Check for cooldown keys in Redis:
   ```bash
   docker exec tyk-redis redis-cli KEYS "cert-cooldown:*"
   docker exec tyk-redis redis-cli TTL "cert-cooldown:check:CERT_ID"
   ```

**Solutions**:
- Ensure `check_interval_seconds` > 0 for periodic checking
- Flush Redis cooldowns: `docker exec tyk-redis redis-cli FLUSHALL`
- Generate certificates with shorter expiry for testing
- Increase `warning_threshold_days` to catch certificates earlier

### Webhooks Not Delivered

**Symptoms**: Events fired but webhooks not received

**Checks**:
1. Check webhook configuration in `tyk.conf`
2. Look for webhook errors in logs:
   ```bash
   docker compose logs tyk-gateway | grep -i "webhook.*error\|webhook.*failed"
   ```

3. Verify webhook endpoint is accessible:
   ```bash
   curl -X POST https://your-webhook-endpoint.com/test
   ```

**Common Issues**:
- Rate limiting (HTTP 429): Webhook endpoint blocking too many requests
- Network issues: Gateway cannot reach webhook endpoint
- Template errors: Webhook template has syntax errors

**Solutions**:
- Check for rate limiting in logs: `grep "429" logs`
- Test webhook endpoint accessibility from gateway container
- Verify template syntax in `templates/default_webhook.json`
- Check for template rendering errors: `grep "template.*error" logs`

### Template Rendering Errors

**Symptoms**: Errors like "can't evaluate field X in type interface {}"

**Cause**: Template references field that doesn't exist in event metadata

**Solution**:
1. Check template file: `templates/default_webhook.json`
2. Verify field names match event metadata structs in code
3. Common fields:
   - `.Meta.CertID`
   - `.Meta.CertName`
   - `.Meta.CertRole` (not `CertificateType`)
   - `.Meta.ExpiresAt` or `.Meta.ExpiredAt`
   - `.Meta.DaysRemaining` or `.Meta.DaysSinceExpiry`
   - `.Meta.APIID`

### Duplicate Events

**Symptoms**: Same certificate generating multiple events rapidly

**Cause**: Cooldowns not working or Redis not connected

**Checks**:
1. Verify Redis connection:
   ```bash
   docker exec tyk-redis redis-cli PING
   ```

2. Check cooldown settings in config
3. Verify cooldown keys being created:
   ```bash
   docker exec tyk-redis redis-cli MONITOR | grep "cert-cooldown"
   ```

**Solutions**:
- Increase `event_cooldown_seconds`
- Ensure Redis is running and connected
- Check Redis connection in gateway logs

### High CPU/Memory Usage

**Symptoms**: Gateway consuming excessive resources

**Cause**: Too frequent checking or large certificate sets

**Solutions**:
- Increase `check_cooldown_seconds` (e.g., 86400 for daily checks)
- Increase `check_interval_seconds` (e.g., 3600 for hourly periodic checks)
- Increase batch flush interval in batcher configuration
- Monitor number of certificates being checked

## Integration Examples

### PagerDuty Integration

Create a webhook receiver that forwards to PagerDuty:

```python
from flask import Flask, request
import requests

app = Flask(__name__)
PAGERDUTY_KEY = "your-integration-key"

@app.route('/certificate-alert', methods=['POST'])
def certificate_alert():
    event = request.json

    # Forward to PagerDuty
    payload = {
        "routing_key": PAGERDUTY_KEY,
        "event_action": "trigger",
        "payload": {
            "summary": event['message'],
            "severity": "warning" if event['event'] == "CertificateExpiringSoon" else "error",
            "source": "tyk-gateway",
            "custom_details": event
        }
    }

    requests.post("https://events.pagerduty.com/v2/enqueue", json=payload)
    return "OK"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888)
```

### Slack Integration

```python
from flask import Flask, request
import requests

app = Flask(__name__)
SLACK_WEBHOOK = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

@app.route('/certificate-alert', methods=['POST'])
def certificate_alert():
    event = request.json

    color = "warning" if event['event'] == "CertificateExpiringSoon" else "danger"

    message = {
        "attachments": [{
            "color": color,
            "title": event['event'],
            "text": event['message'],
            "fields": [
                {"title": "Certificate", "value": event['cert_name'], "short": True},
                {"title": "Role", "value": event['cert_role'], "short": True},
            ]
        }]
    }

    if 'api_id' in event:
        message["attachments"][0]["fields"].append(
            {"title": "API ID", "value": event['api_id'], "short": True}
        )

    requests.post(SLACK_WEBHOOK, json=message)
    return "OK"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888)
```

### Email Integration

```python
from flask import Flask, request
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)

@app.route('/certificate-alert', methods=['POST'])
def certificate_alert():
    event = request.json

    subject = f"[Tyk] {event['event']}: {event['cert_name']}"
    body = f"""
Certificate Alert from Tyk Gateway

Event: {event['event']}
Certificate: {event['cert_name']} (ID: {event['cert_id']})
Role: {event['cert_role']}
Message: {event['message']}

{'API ID: ' + event.get('api_id', 'N/A')}
Timestamp: {event['timestamp']}
"""

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = "tyk-alerts@example.com"
    msg['To'] = "ops-team@example.com"

    with smtplib.SMTP('localhost') as server:
        server.send_message(msg)

    return "OK"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888)
```

## Best Practices

1. **Certificate Lifecycle Management**:
   - Set `warning_threshold_days` to at least 30 days
   - Automate certificate renewal before expiry
   - Monitor webhook delivery to ensure alerts are received

2. **Production Configuration**:
   - Use reasonable cooldown periods (86400 seconds = daily)
   - Set periodic checks to hourly (3600 seconds)
   - Store cooldowns in Redis for persistence across restarts

3. **Testing**:
   - Use short-lived certificates in test environments
   - Test with aggressive cooldowns (10-20 seconds) in development
   - Verify webhook delivery before going to production

4. **Monitoring**:
   - Set up alerts for webhook delivery failures
   - Monitor Redis for cooldown key growth
   - Track certificate expiry dates separately from Tyk

5. **Security**:
   - Use HTTPS for webhook endpoints
   - Authenticate webhook requests (use headers or signatures)
   - Rotate certificates before expiry, don't wait for alerts
