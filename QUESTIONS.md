# Certificate Expiry Monitoring - Implementation Questions

This document collects questions that should be answered before moving from POC to production.

## Architecture & Design

### Monitoring Architecture

**Q1: Is the GlobalCertificateMonitor + CertificateCheckMW split the right approach?**
- Current: GlobalCertificateMonitor handles server/CA certs, CertificateCheckMW handles client/upstream per-API
- Alternative: Single unified monitor for all certificate types
- Tradeoffs: Separation allows per-API configuration but adds complexity

**Q2: Should we use the batcher pattern with background flushing?**
- Current: Certificates are batched and flushed every 5 seconds
- Alternative: Check certificates immediately when encountered
- Tradeoffs: Batching reduces event spam but adds latency

**Q3: Should certificate checking happen in background goroutines?**
- Current: Each API middleware spawns its own goroutines
- Alternative: Central worker pool or single-threaded checker
- Concern: With 100s of APIs, could spawn 100s of goroutines

**Q4: Should we have separate batchers for each certificate role?**
- Current: Separate batcher instances for server, ca, client, upstream
- Alternative: Single batcher with role tagging
- Tradeoffs: Separate batchers allow role-specific configuration

### Cooldown Strategy

**Q5: Should we use in-memory cache + Redis fallback?**
- Current: In-memory cooldown cache with Redis fallback
- Alternative: Redis-only (simpler but slower)
- Concern: What happens if Redis is unavailable?

**Q6: Should check cooldown and event cooldown be separate?**
- Current: `check_cooldown_seconds` (how often to check) and `event_cooldown_seconds` (how often to fire events) are separate
- Alternative: Single cooldown value
- Tradeoffs: Separate allows checking frequently but firing events rarely

**Q7: How should cooldown keys be structured?**
- Current: `cert-cooldown:check:CERT_ID` and `cert-cooldown:event:CERT_ID`
- Alternative: Include role in key: `cert-cooldown:check:ROLE:CERT_ID`
- Concern: Same certificate might have different expiry concerns in different roles

## Configuration

### Default Values

**Q8: What should production default values be?**
- Current POC values (test-friendly):
  - `warning_threshold_days`: 30
  - `check_cooldown_seconds`: 10
  - `event_cooldown_seconds`: 20
  - `check_interval_seconds`: 30
- Suggested production values:
  - `warning_threshold_days`: 30 (keep)
  - `check_cooldown_seconds`: 86400 (daily)
  - `event_cooldown_seconds`: 86400 (daily)
  - `check_interval_seconds`: 3600 (hourly)
- Should defaults be in config file or code?

**Q9: Should check_interval_seconds default to 0 (disabled)?**
- Current: Defaults to some value, periodic checking enabled by default
- Alternative: Default to 0, require explicit opt-in
- Concern: Users might not know feature exists if disabled by default

**Q10: Should configuration be global-only or per-API configurable?**
- Current: Global configuration in `security.certificate_expiry_monitor`
- Alternative: Allow APIs to override thresholds/intervals
- Use case: Critical APIs might want more frequent checks

### Configuration Validation

**Q11: Should we validate configuration values at startup?**
- Examples:
  - Warn if `event_cooldown_seconds` < `check_cooldown_seconds`
  - Error if `warning_threshold_days` is negative
  - Warn if `check_interval_seconds` is very small (< 60)
- Should invalid configs prevent startup or just log warnings?

## Event Payloads & Webhook Delivery

### Event Structure

**Q12: Is the current event payload structure sufficient?**
- Current fields: `event`, `message`, `cert_id`, `cert_name`, `expires_at`/`expired_at`, `days_remaining`/`days_since_expiry`, `cert_role`, `api_id`, `timestamp`
- Missing fields:
  - Certificate serial number?
  - Certificate issuer?
  - Certificate subject alternative names (SANs)?
  - File path for file-based certs?
  - Certificate fingerprint (in addition to cert_id)?

**Q13: Should we include certificate details in events?**
- Security concern: Events might be logged/stored insecurely
- Alternative: Minimal info in event, provide lookup endpoint
- Tradeoff: Convenience vs security

**Q14: Should we fire different event types for different certificate roles?**
- Current: `CertificateExpiringSoon` and `CertificateExpired` for all roles
- Alternative: `ServerCertificateExpiringSoon`, `ClientCertificateExpiringSoon`, etc.
- Tradeoff: More event types = more flexibility but more configuration

**Q15: Should expired certificates continue to fire events?**
- Current: Events fire every event_cooldown period even after expiry
- Alternative: Fire expired event once, then stop
- Use case: Reminder events vs one-time alert

### Webhook Behavior

**Q16: What should happen if webhook delivery fails?**
- Current: Log error and continue
- Alternatives:
  - Retry with exponential backoff
  - Queue for later delivery
  - Fire event to alternative endpoint
- Should we track delivery failures?

**Q17: Should webhook delivery be synchronous or asynchronous?**
- Current: Appears to be synchronous
- Concern: Slow webhooks could block certificate checking
- Alternative: Queue webhooks for async delivery

**Q18: Should we support multiple webhook endpoints per event type?**
- Current: Array of handlers, supports multiple
- Question: Is this tested? Do all webhooks need to succeed?

## Performance & Scalability

### Certificate Volume

**Q19: How does this scale with large numbers of certificates?**
- Scenarios:
  - 10 APIs, 10 certificates each = 100 certificates
  - 100 APIs, 10 certificates each = 1,000 certificates
  - 1,000 APIs, 10 certificates each = 10,000 certificates
- Should we:
  - Limit batch sizes?
  - Limit concurrent checks?
  - Implement sampling (only check subset each interval)?

**Q20: Should we limit background goroutines?**
- Current: Each API with client/upstream certs spawns 2 goroutines (per-API batchers)
- With 1,000 APIs: 2,000+ goroutines just for cert checking
- Alternative: Worker pool pattern

**Q21: Should periodic checks be staggered?**
- Current: All APIs check at same time (every check_interval_seconds)
- Alternative: Randomize/stagger checks across interval
- Benefit: Smooth out resource usage

### Memory Usage

**Q22: What are the memory implications?**
- In-memory cooldown cache stores entry per certificate
- With 10,000 certificates: 10,000 entries × 2 (check + event) = 20,000 cache entries
- Should we:
  - Set max cache size with LRU eviction?
  - Use Redis-only to avoid in-memory cache?
  - Periodically clean expired entries?

**Q23: Do certificate objects get properly garbage collected?**
- Certificates are loaded, parsed, checked, then... ?
- Should we explicitly release references?
- Are there any memory leaks in the batching logic?

## Edge Cases & Error Handling

### Redis Failures

**Q24: What happens if Redis is unavailable?**
- Current: Fallback to Redis for cooldowns, in-memory cache first
- If Redis is down:
  - In-memory cache works but doesn't persist across restarts
  - Multiple gateway instances won't coordinate cooldowns
- Should we:
  - Continue with degraded functionality?
  - Disable monitoring entirely?
  - Fire alerts about Redis being down?

**Q25: What happens on Redis connection flaps?**
- Scenario: Redis goes down briefly, then comes back
- Cooldown keys might be lost or inconsistent
- Could result in duplicate events

### Certificate File Issues

**Q26: What happens if certificate files are deleted/moved?**
- Current: Logs error during periodic check
- Should we:
  - Fire a different event type (CertificateNotFound)?
  - Stop monitoring that certificate?
  - Keep retrying indefinitely?

**Q27: What happens if certificate files are replaced?**
- New certificate might have different expiry date
- cert_id (SHA256) will change
- Should we detect replacements and fire events?

**Q28: What happens if certificate parsing fails?**
- Corrupted file, wrong format, etc.
- Current: Logs warning and skips
- Should we track parsing failures and alert?

### TLS Handshake Issues

**Q29: What happens if client doesn't provide certificate in mTLS?**
- Current: Request fails auth, no certificate to check
- This is expected behavior
- Should we track/log failed auth attempts?

**Q30: What happens if multiple certificates match a client?**
- Certificate chains with multiple certs
- Do we check all of them or just the leaf?

### Lifecycle & Timing

**Q31: What happens during gateway startup?**
- Should we:
  - Check all certificates immediately on startup?
  - Wait for first periodic interval?
  - Delay checks to avoid startup spike?

**Q32: What happens during gateway shutdown?**
- Current: Context cancellation stops goroutines
- Are all goroutines properly cleaned up?
- Should we wait for in-flight checks to complete?

**Q33: What happens during API reload/hot reload?**
- APIs can be added/removed/modified without restart
- Do middleware instances get properly cleaned up?
- Are new APIs immediately monitored?

## Testing & Validation

### Automated Testing

**Q34: What unit tests are needed?**
- Batcher logic
- Cooldown cache
- Certificate expiry calculations
- Event payload generation

**Q35: What integration tests are needed?**
- Full workflow: cert check → event fire → webhook delivery
- Redis integration
- Multiple certificate roles
- Cooldown behavior

**Q36: How do we test certificate expiry in CI/CD?**
- Can't wait 30 days for cert to expire
- Need to generate short-lived certs (we do this in POC)
- Need to mock time?

**Q37: What load/performance tests are needed?**
- 1,000s of certificates
- 100s of APIs
- Concurrent requests triggering client cert checks

### Manual Testing

**Q38: What manual test scenarios should be validated?**
- All 4 certificate roles (server, ca, client, upstream)
- Cooldown behavior (check vs event)
- Redis failover
- Webhook delivery failures
- Gateway restart with existing cooldowns

## Backwards Compatibility & Migration

**Q39: Does this break any existing functionality?**
- New configuration section (no impact if not configured)
- New middleware (only active if API uses mTLS)
- New events (opt-in via event_handlers)
- Verdict: Should be backwards compatible

**Q40: Do existing event consumers need updates?**
- New event types: `CertificateExpiringSoon`, `CertificateExpired`
- Existing consumers might not handle these
- Should we document migration path?

**Q41: Can this be rolled out gradually?**
- Feature flag to enable/disable?
- Rollout per API or global only?
- How to test in production with subset of traffic?

**Q42: What happens with existing certificate management tools?**
- Some users might already monitor certificates externally
- This could result in duplicate alerts
- Should we document how to coordinate?

## Security & Privacy

### Certificate Information Disclosure

**Q43: Should certificate IDs be hashed differently?**
- Current: SHA256 of cert.Leaf.Raw
- Is this sufficient for uniqueness?
- Could cert_id leak information?

**Q44: Should we expose full certificate details in events?**
- Current: cert_name (Common Name) and cert_id
- Not exposing: serial number, SANs, issuer, full cert
- Should we allow configurable verbosity?

**Q45: Should webhook URLs be validated/restricted?**
- Current: Any URL accepted
- Concern: Internal URLs could leak info
- Should we:
  - Blocklist private IPs?
  - Allowlist specific domains?
  - Require HTTPS?

### Webhook Security

**Q46: Should webhook delivery be authenticated?**
- Current: No authentication beyond headers
- Should we support:
  - HMAC signatures?
  - API keys?
  - mTLS for webhooks?

**Q47: Should we redact sensitive info in logs?**
- Webhook URLs might contain secrets
- Certificate names might be sensitive
- What should be redacted?

## Observability & Operations

### Metrics

**Q48: What Prometheus/metrics should be exposed?**
- Suggested metrics:
  - `tyk_cert_checks_total` (counter by role)
  - `tyk_cert_events_fired_total` (counter by event type and role)
  - `tyk_cert_webhook_failures_total` (counter)
  - `tyk_cert_expiring_soon` (gauge by role)
  - `tyk_cert_expired` (gauge by role)
  - `tyk_cert_check_duration_seconds` (histogram)

**Q49: What should be logged and at what level?**
- Current logging:
  - Debug: Periodic checks, batch processing
  - Info: Startup/shutdown
  - Warning: Certificate issues
  - Error: Failures
- Is this appropriate for production?
- Should we reduce log verbosity?

**Q50: How do operators debug issues?**
- Check if monitoring is enabled: Look for specific config
- Check if certificates are being monitored: Look for specific logs
- Check if events are firing: Look for specific logs
- Check cooldown status: Need Redis CLI
- Should we provide debug endpoints?

### Health & Status

**Q51: Should we provide a health/status endpoint?**
- Information to expose:
  - Is monitoring enabled?
  - How many certificates being monitored?
  - When was last check?
  - How many events fired in last 24h?
  - Redis connection status?

**Q52: Should certificate expiry affect gateway health checks?**
- If server cert is expired, gateway might still be "healthy"
- Should expired certs mark gateway as unhealthy?
- Should this be configurable?

## Documentation & Examples

**Q53: Is the current documentation location appropriate?**
- Current: `docs/certificate-expiry-monitoring.md` in internal repo
- Should it be:
  - In main Tyk docs site?
  - In API reference?
  - In separate repo?

**Q54: What additional documentation is needed?**
- Suggested additions:
  - Runbook for operators
  - Troubleshooting guide (expanded)
  - Architecture diagrams
  - Sequence diagrams
  - Migration guide from external cert monitoring

**Q55: What code examples are needed beyond docs?**
- Webhook receiver implementations:
  - PagerDuty (done)
  - Slack (done)
  - Email (done)
  - DataDog?
  - Splunk?
  - Custom alerting system?

## Future Enhancements

**Q56: Should we support certificate auto-renewal?**
- Currently: Just monitoring and alerting
- Future: Integrate with cert-manager, ACME, etc.?
- Out of scope for MVP?

**Q57: Should we support certificate inventory/discovery?**
- List all certificates being monitored
- Show expiry dates, status, roles
- Export as CSV/JSON?
- API endpoint or CLI command?

**Q58: Should we support certificate chains?**
- Current: Only checks leaf certificate
- Should we check intermediate certs?
- Should we check root CA expiry?

**Q59: Should we support CRL/OCSP checking?**
- Check if certificates are revoked
- Fire events for revoked certs
- Performance implications?

**Q60: Should we support certificate usage analytics?**
- Track which certificates are actually used
- Identify unused certificates
- Report on certificate request volume

## Release & Rollout

**Q61: What is the release strategy?**
- Alpha release to internal users?
- Beta with select customers?
- Feature flag for gradual rollout?
- Version compatibility concerns?

**Q62: What are the acceptance criteria for production release?**
- All tests passing?
- Documentation complete?
- Performance benchmarks met?
- Security review completed?
- Customer validation?

**Q63: What is the support plan?**
- Who handles issues/bugs?
- What SLAs apply?
- How are urgent issues escalated?
- What monitoring is in place?

---

## Summary by Category

- **Architecture & Design**: Q1-Q7 (7 questions)
- **Configuration**: Q8-Q11 (4 questions)
- **Events & Webhooks**: Q12-Q18 (7 questions)
- **Performance & Scalability**: Q19-Q23 (5 questions)
- **Edge Cases & Error Handling**: Q24-Q33 (10 questions)
- **Testing & Validation**: Q34-Q38 (5 questions)
- **Backwards Compatibility**: Q39-Q42 (4 questions)
- **Security & Privacy**: Q43-Q47 (5 questions)
- **Observability & Operations**: Q48-Q52 (5 questions)
- **Documentation**: Q53-Q55 (3 questions)
- **Future Enhancements**: Q56-Q60 (5 questions)
- **Release & Rollout**: Q61-Q63 (3 questions)

**Total: 63 questions**

## Priority Classification

### P0 - Must Answer Before Production
Q8, Q9, Q16, Q19, Q24, Q26, Q31, Q33, Q34, Q35, Q39, Q48, Q49, Q61, Q62

### P1 - Should Answer Soon
Q1, Q2, Q5, Q6, Q10, Q11, Q17, Q18, Q20, Q25, Q27, Q32, Q36, Q40, Q43, Q45, Q46, Q50, Q51, Q53, Q54, Q63

### P2 - Nice to Have Answers
Q3, Q4, Q7, Q12, Q13, Q14, Q15, Q21, Q22, Q23, Q28, Q29, Q30, Q37, Q38, Q41, Q42, Q44, Q47, Q52, Q55

### P3 - Future Consideration
Q56, Q57, Q58, Q59, Q60
