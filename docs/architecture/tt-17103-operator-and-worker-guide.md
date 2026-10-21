# Kafka external acknowledgment: operator and worker guide

Status: implementation-branch guide; the feature is not yet ready to ship.

This guide accompanies
[`tt-17103-kafka-manual-acknowledgment.md`](./tt-17103-kafka-manual-acknowledgment.md).
It documents the intended operational contract and the runnable example in
`cmd/tyk-kafka-ack-worker`.

## Stream configuration

Existing streams retain `output_ack`. External acknowledgment is explicit:

```yaml
input:
  tyk_kafka:
    seed_brokers: [kafka-1:9092, kafka-2:9092]
    topics: [employees.eu, employees.us]
    consumer_group: vinci-employees
    acknowledgment:
      mode: external_ack
      component_id: employee-import
      routing: distributed
      checkpoint_limit: 256
      max_in_flight: 10000
      max_in_flight_bytes: 256MiB
      ack_deadline: 30m
      token_ttl: 24h
      missing_ack_policy: redeliver
      redelivery_max_attempts: 8
      redelivery_max_age: 24h
      redelivery_backoff: 1s
      redelivery_max_backoff: 1m
      redelivery_exhausted_policy: pause
      commit_interval: 250ms
      commit_batch_size: 128
```

Use `routing: distributed` for HA. `routing: local` is explicit single-owner
mode and still requires Gateway-managed Redis for its singleton lease. Configure
`dead_letter_topic` when either missing-ack or exhaustion policy is
`dead_letter`.

Map `tyk_kafka_message_id` and `tyk_kafka_ack_token` from the stream message to
the downstream headers `Tyk-Kafka-Message-ID` and `Tyk-Kafka-Ack-Token`.

## Gateway security configuration

Production signing keys should be referenced through Gateway `secrets`:

```json
{
  "secrets": {
    "kafka-ack-2026-09": "<at-least-32-random-bytes>",
    "kafka-reset-operators": "<independent-random-secret>"
  },
  "kafka_acknowledgment_signing": {
    "active_key_id": "ack-2026-09",
    "keys": {"ack-2026-09": "kafka-ack-2026-09"},
    "rotation_overlap_seconds": 86430,
    "shutdown_drain_seconds": 30
  },
  "kafka_offset_reset_authorization": {
    "secret_ref": "kafka-reset-operators"
  },
  "kafka_control_rate_limits": {
    "acknowledgment_requests_per_second": 100,
    "acknowledgment_burst": 200,
    "reset_requests_per_second": 1,
    "reset_burst": 5
  }
}
```

Key material shorter than 32 bytes, the shipped default Gateway secret, missing
references, and partial signing configuration fail closed. The rotation overlap
must cover the longest token TTL plus shutdown drain. Keep the previous key for
that overlap; forced invalidation immediately invalidates live capabilities and
causes safe retry/redelivery. Derivation from a unique Gateway secret of at
least 32 bytes is compatibility-only, not the preferred production setup.

Sessions accessing control paths require `kafka:ack`, `kafka:status`, or
`kafka:offset-reset`; `kafka:*` grants all three. API/session scope still limits
the component. Keyless stream APIs do not expose these paths. Reset uses
`/tyk/streams/{apiID}/{streamID}/kafka/{componentID}/offset/reset/{plan|execute}`
with `x-tyk-authorization`; when `secret_ref` is configured it additionally
requires `x-tyk-kafka-reset-authorization`. A missing or empty referenced secret
and an incorrect header fail closed.

Durable reset audit records contain a server-derived HMAC principal for the
credential that authorized the reset. This distinguishes the shared control
credential from configured dedicated reset credentials, but does not identify
an individual human. There is no caller-controlled actor header and raw secrets
are never stored. Rotating the Gateway or dedicated reset secret changes the
principal; preserve that configuration history when correlating audits across
a rotation. Recovery-supervisor events use a separate fixed actor identity, and
request cancellation does not erase the initiating principal from abort audit
events.

Abort release is represented by `abort_resume_requested` before the Gateway
publishes Resume, followed by `aborted` on success or `abort_resume_failed` on
publication failure. If the intent audit cannot be persisted, Resume is not
published and consumers remain gated for recovery. A failure to persist any
required abort outcome is returned to the reset caller.

Control buckets are process-local and capped at 10,000 requests/s or burst.
Defaults are 100/200 for acknowledgment and 1/5 independently for reset plan
and execute. A `429` includes `Retry-After`; wait and retry idempotently. An
N-Gateway deployment permits approximately N times the per-node rate, so use an
upstream cluster-wide limiter if required. Authentication runs before these
buckets, so WAF/upstream controls remain necessary for brute-force traffic.
Live changes reconfigure existing buckets without granting a fresh burst.

## Downstream transaction rule

The worker must make its business change and idempotency record atomic, then
send the acknowledgment. A crash between those operations creates a safe
duplicate. In production, put the message ID in the same database transaction
as the employee update, with a unique constraint. Do not acknowledge before the
business transaction commits and do not use the highest observed Kafka offset
as a batch acknowledgment.

The included mini-app uses an fsynced journal to make this sequence visible. It
is not a replacement for a transactional production database.

```sh
go test ./cmd/tyk-kafka-ack-worker
TYK_KAFKA_ACK_URL=http://localhost:8080/my-stream/kafka/ack \
TYK_AUTHORIZATION='Bearer <api-credential>' \
WORKER_JOURNAL=/tmp/employee-worker.journal \
go run ./cmd/tyk-kafka-ack-worker
```

It listens on `:8081` by default and accepts `POST /process`. It bounds request
size, records the message ID durably, retries acknowledgment with exponential
delay, and shuts down on SIGINT/SIGTERM.

## Acknowledgment responses

- `200` means the owning connector applied the token. Kafka persistence may
  still be in the bounded commit window.
- `202` means a distributed gateway durably queued the command for its owner.
  It does not mean Kafka is already committed.
- `207` contains mixed per-token results. Production clients must inspect every
  item. The mini-app sends one token and conservatively retries `207`.
- `409`/`410` mean stale or expired capability. Stop retrying that token and
  allow redelivery to supply a new one.
- `429`/`503` and transport errors are retryable with bounded exponential
  backoff. Retrying the same token is idempotent.

## Failure recovery

- Downstream failure before commit: return non-2xx; no acknowledgment is sent.
- Business commit followed by acknowledgment outage: retain the idempotency
  row and retry. A later Kafka redelivery is processed as a duplicate and
  acknowledged again.
- Missing-ack `pause`: the valid retained token may recover the partition. If
  it is unavailable or expired, use a reviewed offset-reset plan; never edit
  the group offset ad hoc.
- Missing-ack `redeliver`: only affected partitions seek back. Expect concurrent
  old/new attempts and depend on idempotency.
- DLQ: Kafka progress advances only after the configured DLQ broker acknowledges
  the write. A DLQ failure leaves the source offset uncommitted and paused.
- Redis outage: remote acknowledgments fail or queue according to the API
  result; never treat an HTTP error as success. Pending durable entries are
  reclaimed after recovery.

## Reset protocol v2 upgrade

Reset protocol v2 uses group-scoped fencing and a new Redis namespace. It is
deliberately incompatible with the earlier per-plan protocol: do not perform a
rolling upgrade or rollback while affected Kafka streams are running.

Before upgrading, stop new reset requests, drain and stop every affected stream
and Gateway, verify that the Kafka consumer groups are empty and that no reset
execution is active, then deploy and restart every Gateway at v2 before enabling
the streams again. Discard and recreate old-protocol plans. A rollback requires
the same full drain and coordinated restart; retain old Redis keys for the
agreed forensic/rollback horizon, but never reuse them as live v2 state. Abort
the rollout if any old-version Gateway or non-empty affected group remains.
Use Kafka `DescribeGroups` (or the approved equivalent) and require zero
members. Require every Gateway status response to show no in-flight records and
no resetting/blocked component, and require reset state to show no running
execution. Automation-held old plan IDs are invalid and must be discarded.

Validate the release candidate with:

```sh
go test -race -short ./ee/middleware/streams/kafka ./ee/middleware/streams
go test -tags=dev ./gateway -run '^TestKafkaExternalAckTwoGatewayDistributedResetE2E$' -count=1
```

## Offset reset runbook

Reset is privileged and separate from normal acknowledgment:

1. Stop or quiesce downstream processing and choose concrete topics/partitions.
2. Call the authenticated reset-plan route with exactly one offset or timestamp
   per target and a reason.
3. Review current position, resolved target, bounds, and replay volume.
4. Execute the returned short-lived plan ID once. Execution is idempotent.
5. Keep consumers stopped if any target is partial or unverifiable; follow the
   durable execution record and operator reconciliation instructions.
6. After verified resume, monitor replay lag and use replay generation in the
   downstream deduplication decision.

The reset coordinator fences one leader, quiesces every registered connector,
makes them leave the Kafka group, verifies the group is empty, alters and
verifies offsets, publishes resume, and reconstructs consumers. A non-Tyk or
unexpected active group member causes the operation to fail closed.

If Redis becomes uncertain, participants stop polling, leave the group, and
remain gated until durable membership/barrier state is re-established; they
reconstruct the Kafka client before polling resumes. Expired abandoned barriers
recover only through fencing plus a durable `expired_barrier_recovered` event.
Audit storage is bounded at 10,000 events per component. Alert before it fills,
export/archive through the approved audit pipeline, and never delete unexported
records. A full or unverifiable journal fails closed and may leave consumers
gated until audit capacity is restored and the reset is reconciled.

## Operational checks

Import the checked-in [Grafana dashboard](assets/tt17103/grafana-dashboard.json)
and load the [Prometheus recording and alert rules](assets/tt17103/prometheus-rules.yaml).
They use the Prometheus export names `tyk_streams_kafka_events_total` and
`tyk_streams_kafka_state`, with bounded `api`, `stream`, `component`, and
`kind` labels. Tune alert `for` durations to the deployment SLO; do not remove
the reset, commit-failure, paused-partition, or dead-letter signals.

Alert on growing uncommitted lag, paused partitions, capacity rejects, commit
failures, oldest Redis acknowledgment age, poison/dead-letter counts, reset
failures, and singleton-lease loss. During reload/unload verify that the former
consumer leaves its group and that only one replacement owns each partition.
Never log tokens, Kafka credentials, or unredacted broker errors to callers.

This guide does not waive the remaining ship gates: full CI and coverage,
multi-broker/version/security compatibility, TLS/mTLS/SASL results, two-Gateway
chaos/reset acceptance, performance/soak, independent reviews, and customer
validation are still required.
