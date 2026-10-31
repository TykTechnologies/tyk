# TT-17103: Kafka Manual Acknowledgment and Offset Control

Status: implementation plan
Related work: TT-17101, PRs #8174, #8175, #8176, and #8177
Target component: Tyk Streams Enterprise Edition

This document is the implementation contract, not a declaration that the
feature is ready to ship. A phase is complete only when its Definition of Done
tests pass in CI and the operational requirements below are implemented.

## Executive summary

Tyk Streams will provide an asynchronous, at-least-once Kafka-to-HTTP delivery mode in which downstream applications acknowledge completed business processing independently of the HTTP delivery response.

The existing `tyk_kafka` PoC was the starting point. This tree has removed its
independent Sarama offset handler and gives one Tyk-owned franz-go connector
responsibility for:

- Kafka consumer-group membership and partition assignments;
- bounded in-flight delivery and per-partition backpressure;
- externally supplied acknowledgments;
- contiguous offset advancement;
- commits made by the active group member;
- rebalance and shutdown behavior;
- controlled offset reset and replay.

This design provides at-least-once delivery. It intentionally does not claim exactly-once execution of arbitrary downstream HTTP side effects. Downstream applications must use the supplied message identity as an idempotency key.

## Implementation checkpoint

The current development tree is a production-shaped implementation branch, not
a release candidate. The statements below describe code present in this tree;
"verified" means only the specifically named local or container test was
observed passing. It does not imply that GitHub CI, the supported platform
matrix, or the complete Definition of Done passes.

| Area | Current state | Remaining ship gate |
| --- | --- | --- |
| Connector | Custom `tyk_kafka` input built on franz-go; Sarama is absent from production; assignment/revocation/loss state is partition scoped; teardown and commit workers are bounded and joined; real multi-broker failover and dynamic-topic lifecycle tests pass | Repeat the observed cases in required CI, complete the Product-approved compatibility matrix, and extend long-running rebalance chaos |
| Manual acknowledgment | Signed scope/group/owner tokens, ordered windows, gap-safe contiguous commits, serialized commit batching, stale fencing, and idempotent retry after an ambiguous commit response | Complete the full broker failure matrix in CI and independently review commit/rebalance correctness |
| Backpressure | Hard record/byte admission, bounded pending fetch behavior, derived franz-go fetch ceilings, and pause/resume are implemented | Benchmark and soak many dynamic partitions; prove acceptable throughput without weakening the bounds |
| Missing acknowledgments | Partition-scoped in-place redelivery, pause recovery, synchronous Kafka DLQ writing, and bounded exponential attempt/age policy are implemented; real Gateway redelivery, pause, DLQ success/failure, and retention cases pass | Complete the 24-hour topology soak and deployment acceptance for operational defaults and alerts |
| Key lifecycle | Shared key provider, scoped claims, rotation overlap checks, and owner/group/nonce claims are implemented | Security review the key source, forced invalidation, log redaction, and rotation operations |
| HA routing | Gateway-managed Redis transport, Kafka-assignment fencing, heartbeat/expiry, pending recovery, poison handling, aggregate bounds, and distributed owner workers are implemented; real Redis tests prove native TTL behavior is not weakened by ±24-hour caller clock skew, the Claim/Heartbeat WATCH race regression passes, and the corrected topology harness passed a 3-minute disruption qualification | Extend the passing qualification to long-duration crash/rebalance/network-partition acceptance and Redis load validation |
| Local routing | Explicit `routing: local` acquires a component-scoped Gateway-managed Redis singleton lease with heartbeat, unload release, and crash expiry | Run the two-manager contention/takeover test in required CI environments and document Redis availability as a prerequisite |
| Offset reset | Plan/execute validation, kadm adapter, durable Redis state/lease/fencing, participant heartbeat, group-wide quiescence, verification, resume, and reconstruction are implemented; the credential-attributed two-Gateway reset topology passes repeatedly | Extend crash injection across every durable transition and obtain control-plane/security review approval |
| Gateway API | Strict bounded acknowledgment/reset handlers, permission checks, generic errors, durable credential-principal audit events, and independent lifecycle-scoped acknowledgment/reset rate limits exist; final control-plane route and negative authorization cases pass | Repeat in clean CI and obtain security review approval |
| Identity | Event/delivery identities include cluster/topic incarnation and replay generation; topic recreation and stale-token fencing tests pass | Complete the Product-approved legacy/platform matrix and ratify retry/replay deduplication semantics with the customer |
| Observability | Bounded status and metrics integration exist | Validate dashboards, alerts, label cardinality, audit durability, and log redaction operationally |
| Verified local evidence | The complete current-tree non-short Kafka package passed in 410.004s with 82.0% statement coverage; Gateway Kafka group passed in 101.760s; HA passed repeatedly; the current credential-attributed reset-v2 two-Gateway distributed-reset path passed twice in 25.37s and 22.05s; after correcting producer idempotence, offset-based assertions, and bounded history retrieval, the final reset-v2 tree passed the exact-offset-correlated 3-minute two-Gateway Kafka/Redis disruption qualification in 202.37s with a 3-second restart cadence; a later final-tree soak remained healthy for approximately 11 hours with continuous Gateway churn and successful Redis pause/unpause recovery before intentional operator stop; a real regression also held delivered records unacknowledged beyond franz-go's default five-second commit interval and observed Kafka remain uncommitted; the enhanced four-cycle reload/leak test passed on the current tree in 16.06s with broker-socket, franz-go goroutine, membership, controller, and `stream.Run` cleanup assertions; a real 100-record three-mode performance smoke passed; broker-loss reset abort/retry passed in 19.80s; TLS/mTLS/SASL, Kafka 7.5/7.8, Redis 6/7 including native-TTL acknowledgment/reset skew and heartbeat cleanup races, three-broker failover, retention, DLQ, and security cases have observed real passes | Complete repository CI/race from a clean checkout and preserve results in required CI; the intentionally stopped run does not establish the 24-hour topology soak, an accepted performance SLO, or every repository/platform gate |

Until every remaining gate is closed, this work is an implementation branch and
must not replace the current production Kafka input.

### Prioritized release blockers

The work is ordered by safety and architectural dependency, not by apparent
implementation size:

1. Make the complete two-Gateway Kafka-plus-Redis acknowledgment, rebalance,
   crash, and reset topology pass repeatedly under the race detector.
2. Preserve the observed three-broker, Kafka 7.5/7.8, Redis 6/7, dynamic-topic,
   and retention passes; expand them to the Product-approved support matrix and
   complete broker/network failure coverage.
3. Preserve the observed passing TLS/mTLS positive and negative test and the
   observed PLAIN/SCRAM-SHA-256/SCRAM-SHA-512 matrix, and obtain repeatable
   clean-CI evidence; individual local container runs are not release evidence.
4. Pass performance comparison, bounded-memory load, and twenty-four-hour soak
   gates with broker, Redis, worker, and Gateway restarts.
5. Complete security/threat-model, architecture, QA/DoD, Innersource, product,
   and external code reviews; pass repository CI and its quality/coverage gates.
6. Demo a release-candidate build to VINCI, validate the asynchronous contract
   and recovery operations, and record customer acceptance.

No performance optimization may weaken contiguous commit ordering, fencing, or
the hard delivery bounds.

## Why a Tyk-owned connector is required

Yes: asynchronous, out-of-band acknowledgment for complex Kafka consumer-group
cases requires a connector that owns the active consumer lifecycle. The existing
PoCs already introduced this as `tyk_kafka`, derived from Bento's franz-go input.
That is useful groundwork, but the original PoC exposed an independent Sarama
handler which could only alter broker-stored offsets; it could not safely control
the active franz-go fetch position, assignment epoch, backpressure, or rebalance
barriers.

This does not require implementing the Kafka protocol or consumer client from
scratch. Tyk should continue using franz-go and keep the custom surface narrow:
assignment hooks, bounded admission, acknowledgment windows, serialized commits,
distributed routing, and reset orchestration. Those semantics cannot be composed
reliably as an HTTP handler beside an opaque stock connector.

### PoC inventory and reuse answer

The existing PoCs were inspected and are not being discarded. PRs #8176/#8177
already contained the custom `tyk_kafka` component, derived from Bento's
franz-go input, plus the initial manual-commit/offset-control experiments. The
production branch reuses that connector direction and franz-go configuration
surface. It replaces the separate Sarama control client, raw downstream offset
commit API, first-topic assumptions, and incomplete lifecycle behavior. In
short: this is a Tyk-owned connector built on the mature franz-go Kafka client;
it is not a new implementation of the Kafka wire protocol.

## Goals

- Never commit past an unacknowledged record.
- Redeliver every record that was not durably committed after a crash, restart, or rebalance.
- Bound memory and delivery concurrency independently for every topic partition.
- Support multiple topics, partitions, gateway instances, consumer-group rebalances, batches, TLS, SASL, and dynamic topic discovery.
- Permit offset- and timestamp-based replay without mixing replay with ordinary acknowledgments.
- Reject forged, stale, cross-stream, cross-group, and cross-assignment acknowledgments.
- Preserve the existing synchronous Bento acknowledgment behavior as the default.
- Avoid a permanent fork of unrelated Bento components.
- Expose sufficient metrics and state for operators to diagnose blocked partitions and replay progress.

## Non-goals

- Exactly-once downstream business processing without cooperation from the downstream application.
- Atomic transactions spanning Kafka and an arbitrary HTTP application's database.
- Allowing a downstream application to commit arbitrary Kafka offsets.
- Resetting offsets silently while previously delivered work remains valid.
- Changing the semantics of the existing `kafka_franz` component.

## Delivery modes

The connector supports two explicit modes. There is no implicit behavior change for existing streams.

### `output_ack` mode

This is the existing behavior and remains the default. A successful Bento output acknowledgment marks the message complete. An HTTP downstream must hold its response open until business processing succeeds.

### `external_ack` mode

A successful output response means only that the downstream accepted delivery. Kafka progress is controlled by a later acknowledgment containing a Tyk-issued token.

In this mode:

- output success does not release the manual acknowledgment checkpoint;
- output failure continues to use Bento retry/nack behavior;
- each delivered record receives a signed acknowledgment token and stable idempotency key;
- `checkpoint_limit` bounds unacknowledged records per partition;
- the partition is paused when its window is full and resumed only when the contiguous acknowledgment watermark advances.

## Proposed stream configuration

```yaml
input:
  tyk_kafka:
    seed_brokers:
      - kafka-1:9092
      - kafka-2:9092
    topics:
      - employees.eu
      - employees.us
    consumer_group: vinci-employees

    acknowledgment:
      mode: external_ack
      checkpoint_limit: 256
      max_in_flight: 10000
      max_in_flight_bytes: 256MiB
      ack_deadline: 30m
      missing_ack_policy: redeliver
      redelivery_max_attempts: 8
      redelivery_max_age: 24h
      redelivery_backoff: 1s
      redelivery_max_backoff: 1m
      redelivery_exhausted_policy: pause
      # dead_letter_topic: employees.processing.dlq
      token_ttl: 24h
      routing: distributed
      commit_interval: 250ms
      commit_batch_size: 128

    auto_offset_reset: earliest
    tls: {}
    sasl: []
```

Compatibility rules:

- `acknowledgment.mode` defaults to `output_ack`.
- The PoC field `disable_auto_commit` is deprecated. During migration, `disable_auto_commit: true` without `acknowledgment.mode` fails validation rather than creating a consumer that never commits.
- `external_ack` requires a non-empty `consumer_group`.
- `dead_letter_topic` is required when the direct missing-ack policy or the
  redelivery-exhaustion policy is `dead_letter`.
- `acknowledgment.checkpoint_limit` replaces the existing top-level limit in `external_ack` mode; configuring both is rejected.
- Explicit topic-partition assignment and consumer-group mode remain mutually exclusive.
- Regex topics are supported for acknowledgment only after a concrete topic has been assigned. Reset requests always name a concrete topic.
- `routing: local` is explicit opt-in and acquires a component-scoped singleton
  lease through the Gateway-managed Redis client. A second live instance fails
  that stream's setup; unload releases the lease and crash expiry permits
  takeover. Production multi-gateway routing normally uses `distributed`.
- Each `tyk_kafka` input has a stable component ID. API, stream, and component ID together identify its controller, allowing broker inputs with multiple Kafka connectors or groups without ambiguous routes.

## Downstream delivery contract

Each record exposes these immutable values to processors and outputs:

- `kafka_topic`
- `kafka_partition`
- `kafka_offset`
- `kafka_timestamp_unix`
- `tyk_kafka_message_id`
- `tyk_kafka_delivery_id`
- `tyk_kafka_replay_generation`
- `tyk_kafka_ack_token`

The HTTP output should normally map the last two values to headers:

```text
Tyk-Kafka-Message-ID: <stable topic/partition/offset identity>
Tyk-Kafka-Ack-Token: <signed opaque token>
```

The target message ID identifies the Kafka event using logical cluster ID, topic incarnation, partition, and offset. The delivery ID additionally identifies replay generation. A separate attempt identity will be added only if output retry hooks can update it reliably; current retries reuse the same delivery ID and acknowledgment capability. The downstream uses event ID to suppress crash-window duplicates, but includes replay generation in its deduplication key when an intentional replay must execute the business operation again. The acknowledgment token is capability-scoped and must not be interpreted by the downstream application.

If the downstream receives a request but Tyk does not receive the HTTP response, Bento retries. Retries for the same assignment, replay generation, and record use the same delivery ID, acknowledgment capability, and record state. Multiple attempts cannot advance the watermark more than once.

For batched output, every record retains its own ID and token. A batch acknowledgment request may contain multiple tokens, and the server returns a result for each token. A batch is never represented by a single highest offset.

## Acknowledgment API

Acknowledgment is distinct from administrative offset control:

```http
POST /{streamID}/kafka/ack
Authorization: <normal API credential plus kafka:ack permission>
Content-Type: application/json

{
  "tokens": ["<opaque-token>"]
}
```

Possible outcomes:

- `200`: every token was valid and applied to the owner's in-memory window; this can still produce a safe duplicate if the owner fails before Kafka commit;
- `202`: every token was durably appended to the distributed router before the response, but has not necessarily been applied;
- `207`: a multi-token request has mixed per-token results; the response supplies stable result and retry codes for every item;
- `400`: malformed request;
- `401` or `403`: authentication or scope failure;
- `409`: token belongs to an expired assignment epoch or an invalidated replay generation;
- `410`: token expired;
- `413`: request or token count exceeds configured bounds;
- `503`: the owning consumer is unavailable and durable routing is unavailable.

The API never accepts raw topic, partition, or offset values for normal acknowledgments.

JSON decoding must use a bounded body, reject unknown fields, require at least one token, cap tokens per request, and return generic client errors while logging internal details securely.

## Acknowledgment token

The token is versioned and authenticated with a rotatable Tyk secret. The current implementation protects the following claims; their operational key lifecycle still requires security review:

- token format version;
- API and stream identity;
- consumer group;
- owner gateway instance;
- assignment epoch or generation nonce;
- replay generation;
- topic, partition, and record offset;
- issued-at time;
- a nonce if deterministic per-record capabilities are not retained.

An HMAC-signed compact token is sufficient if revealing topic/group names is acceptable. Otherwise the claims are authenticated and encrypted. Token validation supports the current signing key and a bounded set of previous keys for rotation.

External acknowledgment must fail closed unless its root signing material is at least 32 bytes. The preferred production configuration uses `kafka_acknowledgment_signing` key IDs whose values reference entries in the Gateway secrets map. For compatibility, an installation may derive the acknowledgment key from a unique Gateway `secret` of at least 32 bytes; an empty, shorter, or shipped-default Gateway secret is rejected. Configuring only an active key ID or only key references is also rejected rather than silently falling back.

Tokens are scoped to one delivered record and are idempotent. They cannot be reused across streams or after reset/reassignment. Secrets and complete tokens must never appear in logs or analytics.

Tokens carry a key ID. Signing keys come from a Tyk-managed, cluster-consistent secret source. Rotation overlap is at least the maximum token lifetime plus shutdown drain time. Removing a key that still has live in-flight tokens is rejected unless an operator explicitly invalidates those deliveries.

## Connector architecture

Only the Kafka connector owns franz-go's active `kgo.Client`. HTTP handlers communicate with the connector through interfaces; they never construct a second Kafka client for commit operations.

The following is target-shape pseudocode; concrete request/result types may evolve:

```go
type AcknowledgmentController interface {
    Acknowledge(ctx context.Context, tokens []string) ([]AckResult, error)
    Status(ctx context.Context) ControllerStatus
}

type OffsetController interface {
    PlanReset(ctx context.Context, request ResetRequest) (ResetPlan, error)
    ExecuteReset(ctx context.Context, plan ResetPlan) error
}
```

Internally the connector contains:

- an assignment registry keyed by concrete topic and partition;
- a partition-local acknowledgment window;
- a serialized poll/control event loop;
- a commit aggregator;
- an acknowledgment router;
- a reset/replay coordinator;
- lifecycle hooks for assignment, revocation, shutdown, and reload.

All franz-go calls that affect consumption position or group state are serialized with polling and rebalance callbacks. HTTP goroutines never call `SetOffsets`, `CommitOffsets`, pause, or resume directly.

## Partition acknowledgment window

Each assigned partition maintains:

```text
assignment epoch
replay generation
next expected record offset
highest contiguous acknowledged offset
ordered in-flight records
paused state
last committed next-offset
```

Example:

```text
delivered:     100 101 102 103
acknowledged:  yes  no  yes yes
commit value:  101
```

After record 101 is acknowledged, the window advances through 103 and Kafka may be committed to next-offset 104.

Rules:

- Only offsets actually delivered during the current assignment epoch can be acknowledged.
- Acknowledging a record twice is successful and has no additional effect.
- A higher acknowledgment never closes a lower gap.
- Lower Kafka offset commits are never emitted accidentally after a newer watermark.
- Commits contain the next offset, while APIs and message metadata consistently describe record offsets.
- The target steady-state behavior pauses only the partition that reaches `checkpoint_limit`; the current conservative global-capacity path can pause every assignment and must be refined without weakening its bound.
- Commit batching may delay persistence briefly but must not advance beyond the contiguous watermark.
- Contiguity follows the ordered records actually returned by Kafka, not arithmetic `offset + 1`; compacted, aborted, control, or retention-created gaps are valid.
- The committed position is the next safe Kafka position following the contiguous acknowledged record sequence, with leader epoch retained where available.

The state may be held in memory because Kafka's committed watermark is the durable recovery boundary. Losing newer acknowledgments can create duplicates but cannot create data loss. A `200` acknowledgment therefore means accepted by the owner, not necessarily durably committed to Kafka; downstream applications must retain their idempotency record and safely acknowledge a redelivery. Optional distributed persistence may reduce duplicates, but must never advance Kafka without a valid acknowledgment.

### Missing acknowledgment and expiry recovery

Every in-flight record has an acknowledgment deadline distinct from token cryptographic expiry. The target behavior applies the configured policy:

- `redeliver` (default): invalidate the current capability, issue a new delivery attempt for the same record, and keep the partition watermark behind it;
- `pause`: keep the partition paused and raise an operator-visible alert until an authenticated retry/renewal action is taken;
- `dead_letter`: send the record and failure context to an explicitly configured durable DLQ, and advance only after the DLQ write is acknowledged.

Concurrent processing of an expired delivery and its redelivery is possible, so downstream idempotency remains mandatory. An old token is rejected after a new capability generation is issued. The implementation uses bounded exponential delay plus configured maximum attempts and age. Exhaustion explicitly pauses for operator recovery or uses the durable DLQ policy; there is no implicit unsafe “skip.” Redelivery clears and seeks only affected partitions through the owning franz-go client rather than restarting the whole connector.

### Hard resource bounds

`PauseFetchPartitions` alone is not a hard bound because one poll can return many records and franz-go buffers fetch data. The production connector therefore must enforce all of:

- per-partition record capacity;
- stream-wide `max_in_flight` record capacity;
- stream-wide `max_in_flight_bytes` capacity;
- franz-go maximum poll-record and fetch-byte settings derived from those limits;
- a bounded handoff queue that never delivers records for which no window capacity was reserved.

The current implementation establishes the bound conservatively with one-record polling, one bounded pending fetch, admission checks, and derived fetch ceilings. Before release it should be benchmarked and, if needed, replaced by a reservation-aware bounded queue without changing the contract. Records returned by a poll beyond immediately available delivery capacity must remain in that bounded connector-owned structure or cause fetching to stop before another poll; they must not be copied into unbounded queues. Dynamic topic/partition discovery shares the global limits. The consumer continues polling/heartbeating as required even when every assigned partition is paused.

## Multi-instance acknowledgment routing

In a gateway cluster, the instance receiving `/ack` may not own the relevant partition. The token identifies the partition, assignment epoch, consumer group, and owner, and the router resolves the current partition route. Kafka assignment identity, not an untrusted routing hint, fences the active Redis owner.

`distributed` routing uses a durable Tyk-supported Redis transport. Redis Streams
is the preferred production shape; the current hash/ZSET adapter is a semantic
prototype and must pass bounded-load benchmarks or be replaced before release:

1. The ingress gateway validates the token signature, scope, and expiry.
2. Local-owner tokens enter the connector event loop directly.
3. Remote-owner tokens are appended to a bounded partition route associated with the authoritative current owner.
4. The owner consumes, validates the current epoch, and applies them idempotently.
5. Entries are acknowledged and trimmed only after application or definitive stale-token rejection.

Requirements:

- no fire-and-forget Redis Pub/Sub for acknowledgments;
- bounded retention, dead-letter metrics, and backpressure when the router is unavailable;
- owner heartbeat and expiry;
- no rerouting an old token to a new owner after rebalance;
- stale acknowledgments fail closed and the record is redelivered from Kafka if necessary.

Redis ownership and reset records use compare-and-swap fencing epochs. Router consumers recover pending entries after owner failure, never trim entries still pending, quarantine poison entries, and bound per-owner and global backlog. A token's encoded owner is only a routing hint; the current fenced assignment is authoritative. Redis failure does not permit unsafe Kafka advancement. Depending on configured policy, local owners may continue accepting local acknowledgments, while remote acknowledgments return `503`.

## Rebalance behavior

### Assignment

- Create a new cryptographically random assignment epoch.
- Initialize the window at Kafka's assigned starting offset.
- Publish ownership for distributed routing.
- Start fetching only after local state is ready.

### Revocation

- Stop issuing new deliveries for revoked partitions.
- Reject or stop routing new tokens for the closing epoch.
- Apply acknowledgments already serialized before the revocation barrier.
- Synchronously commit only the highest contiguous acknowledged watermark.
- Remove ownership and invalidate all remaining tokens.
- Discard uncommitted window state; Kafka will redeliver it to the next owner.

`BlockRebalanceOnPoll` may be used only with a bounded processing/barrier duration. Heartbeats, session timeout, and maximum poll interval must be tested under a full checkpoint window and slow downstream behavior.

Commit requests and completions carry assignment epoch. Commits are serialized, generation-aware, monotonically fenced by the local watermark, and retried with bounded backoff. A delayed completion from a revoked epoch can neither update new state nor cause a lower commit. “Commit succeeded but response was lost” is handled as an idempotent retry and verified against Kafka when necessary.

## Shutdown, API reload, and failures

Graceful shutdown follows the same barrier as revocation:

1. stop fetching and issuing tokens;
2. stop accepting new local acknowledgments;
3. drain already serialized acknowledgments for a bounded duration;
4. synchronously commit the contiguous watermark;
5. invalidate the epoch and unregister ownership;
6. close the one franz-go client;
7. stop the stream.

An ungraceful crash simply loses uncommitted in-memory state. Kafka reassigns the partitions and redelivers from the last committed watermark.

Manager unload, dry-run validation, and API reload must not create additional Kafka clients. Dry-run validates configuration without dialing Kafka. Every created client has exactly one owner and a guaranteed close path.

## Offset reset and replay

Offset reset is a privileged control-plane operation, not a stream data-plane acknowledgment:

```http
POST /tyk/streams/{apiID}/{streamID}/kafka/{componentID}/offset/reset/plan
x-tyk-authorization: ...
x-tyk-kafka-reset-authorization: ...

{
  "consumer_group": "vinci-employees",
  "targets": [
    {"topic": "employees.eu", "partition": 0, "offset": 1200},
    {"topic": "employees.us", "partition": 2, "timestamp_ms": 1780000000000}
  ],
  "reason": "replay failed ETL run"
}
```

The plan endpoint resolves timestamps, validates topic membership and bounds, reports current and target offsets, estimates replay volume where possible, and returns a short-lived plan ID. Exactly one of `offset` and `timestamp_ms` is accepted per target.

Reset is supported only when the consumer group is exclusively owned by the named Tyk API, stream, and connector. A non-Tyk member or another stream using the group makes planning or execution fail. Execution requires the plan ID and uses a durably recorded, fencing-token-protected group-wide state machine:

1. acquire a reset lease for API, stream, and consumer group;
2. quiesce all participating gateway instances;
3. stop fetching and invalidate outstanding tokens by incrementing replay generation;
4. commit only existing contiguous acknowledgments unless the explicit reset policy says to abandon them;
5. make every Tyk consumer leave the group while retaining its existing client as the usable franz-go/kadm administrative connection, then verify through Kafka group description that the group is empty;
6. alter and verify consumer-group offsets through that fenced kadm adapter;
7. verify stored offsets;
8. publish fenced resume, close clients to force reconstruction, reset local windows, and restart consumers;
9. verify new assignments begin at the requested positions;
10. write an audit event and release the lease.

Kafka does not guarantee transactional atomicity across every target in a multi-partition reset. The durable reset record stores requested, resolved-before, desired-after, applied, and verified state per target. Execution is idempotent and consumers remain stopped until every target is verified. After partial success or coordinator failure, a new reset leader uses the fencing token and durable record to retry/roll forward; if convergence cannot be proven, the group remains stopped for explicit operator reconciliation. Crash recovery is defined for every state transition. Tests directly cover partial-target resume, ambiguous barrier publication, lease expiry/takeover, broker-loss abort/retry, audit-full failure, and client reconstruction; an exhaustive transition-by-transition crash-injection matrix remains a release-evidence gate.

Reset supports multiple concrete topics and partitions in one plan. Concurrent resets, configuration reloads, and ordinary acknowledgments are rejected or queued behind the reset barrier. Reset leases alone are not trusted for safety: every mutation checks the durable fencing token so an expired or partitioned former leader cannot continue.

Reset protocol v2 is a breaking durable-state migration from the earlier
per-plan lease model to group-scoped fencing. Mixed old/new Gateway operation is
unsupported: old and v2 nodes do not share one lease/barrier truth and therefore
must never control the same group concurrently. Rollout and rollback both
require a coordinated drain, confirmation that affected consumer groups are
empty and no reset is running, and a full-cluster Gateway restart before streams
are re-enabled. Existing old-protocol plans must be discarded and replanned;
legacy Redis state is retained for the agreed forensic horizon and is rejected
fail-closed by v2, not silently migrated. This coordinated rollout is a release
gate and ordinary same-version reload tests are not upgrade-safety evidence.

The existing public `/{streamID}/kafka/offset/commit` and `/reset` PoC routes are removed. No raw arbitrary-offset commit endpoint is exposed to downstream workers.

## Security and authorization

- `/ack` requires normal API authentication plus a dedicated `kafka:ack` permission. A keyless API does not make acknowledgment or reset endpoints keyless.
- Reset always uses the protected Tyk control plane. Operators can additionally
  configure `kafka_offset_reset_authorization.secret_ref` to require a dedicated
  credential from `secrets` in `x-tyk-kafka-reset-authorization`; this check is
  constant-time and fails closed when the reference is missing or empty. For
  backward compatibility, deployments without `secret_ref` retain the existing
  global control-plane credential behavior. Migration is to configure the
  secret reference on every Gateway instance, distribute the dedicated header
  only to reset operators, update automation, and then reload the cluster.
- Access rights are restricted by API/session scope, stream component, and the
  fixed consumer group configured on that component. There is no independent
  per-group or environment authorization claim in the current implementation.
- Every reset is audit logged with a bounded, server-derived credential
  principal hash, reason, plan, old offsets, requested offsets, resolved
  offsets, result, and correlation ID. The principal distinguishes the shared
  control-plane credential from each configured dedicated reset credential; it
  is not a human identity. It is an HMAC and neither raw credentials nor a
  caller-supplied actor header enter the event. Credential/config rotation
  intentionally changes the principal. Supervisor recovery retains its fixed,
  separately identifiable actor hash. Abort cleanup preserves the initiating
  principal after request cancellation.
- Abort release is audit-ordered: durable `abort_resume_requested` is required
  before publishing Resume, `aborted` records success, and
  `abort_resume_failed` records a failed publication. If the intent cannot be
  audited, Resume is not published and consumers remain gated; any of these
  audit failures is returned to the operator rather than silently discarded.
- Rate limits apply independently to acknowledgment and reset APIs.
- Kafka errors, broker addresses, credentials, certificate paths, and token contents are not returned to callers.
- TLS and SASL configuration is consumed once by the franz-go connector; there is no lossy translation into Sarama configuration.

### Control API rate-limit operation

`kafka_control_rate_limits` accepts the following per-Gateway settings:

| Setting | Default | Maximum |
| --- | ---: | ---: |
| `acknowledgment_requests_per_second` | 100 | 10,000 |
| `acknowledgment_burst` | 200 | 10,000 |
| `reset_requests_per_second` | 1 | 10,000 |
| `reset_burst` | 5 | 10,000 |

Zero or negative runtime values select the safe defaults; schema-validated
configuration rejects negative values. Values above the maximum are clamped.
Acknowledgment aliases share one bucket for an API/stream/component. Reset plan
and execute use separate lifecycle-scoped buckets. Rejected requests return
`429` and an integer `Retry-After` header.

These limits are intentionally node-local. In an HA deployment, effective
aggregate capacity is the configured capacity multiplied by the number of
Gateways that receive control traffic. Use an upstream distributed limiter if a
cluster-wide ceiling is required. Existing handlers and registered reset
controllers read current Gateway configuration on requests; reload changes do
not reset accumulated allowance or grant a fresh burst.

Normal Gateway authentication, the `kafka:*` permission check, and the optional
dedicated reset credential are evaluated before these buckets. Consequently the
buckets protect parsing and Kafka/control work, but are not a credential
brute-force defense. Apply the standard edge/WAF authentication-failure limits
where that threat is in scope.

## Observability

Metrics, partitioned by API/stream and carefully bounded labels, include:

- records fetched, delivered, acknowledged, redelivered, and expired;
- current in-flight records and configured limit;
- highest delivered, contiguous acknowledged, and committed offsets;
- commit attempts, latency, batch size, and failures;
- paused partitions and pause duration;
- invalid, stale, duplicate, and remotely routed acknowledgments;
- rebalance count and barrier duration;
- router backlog, oldest entry age, failures, and dead letters;
- reset plans, executions, failures, and replay lag.

Logs include API, stream, group hash, topic, partition, assignment epoch, replay generation, and correlation ID where appropriate. Raw credentials and acknowledgment tokens are excluded.

A read-only status endpoint reports assignment ownership, partition watermarks, in-flight counts, paused state, router health, and reset state without exposing tokens or secrets.

Checked-in operational starters are the [Prometheus rules](assets/tt17103/prometheus-rules.yaml)
and [Grafana dashboard](assets/tt17103/grafana-dashboard.json). They reference
the actual Prometheus exporter names `tyk_streams_kafka_events_total` and
`tyk_streams_kafka_state`; `go test ./internal/otel -run
TestKafkaObservabilityAssetsUseExportedMetrics` validates their syntax and
prevents metric-name drift. Deployment-specific thresholds and alert routing
still require production acceptance.

## Testing strategy and Definition of Done

### Unit tests

- Ordered, duplicate, and out-of-order acknowledgments.
- Gap closure and contiguous watermark advancement.
- No lower commit after a higher committed watermark.
- Record-offset versus committed-next-offset conversion.
- Window full, partition pause, gap closure, and resume.
- Token signing, rotation, expiry, tampering, scope, epoch, and replay generation.
- Multi-token partial results and request validation.
- Offset/timestamp reset-plan validation and boundary handling.
- Missing-ack timeout, token renewal/redelivery, pause, and DLQ policies.
- Poll batches exceeding partition capacity and enforcement of global record/byte bounds.
- Kafka offset gaps, leader epochs, truncation, and `OffsetOutOfRange` with an open window.
- Manager creation, dry-run, unload, reload, and close ownership.

### Deterministic concurrency tests

- Acknowledgment concurrent with polling.
- Acknowledgment concurrent with revocation.
- Reset concurrent with acknowledgment and API reload.
- Commit callback delayed across rebalance.
- Router redelivery and duplicate acknowledgment.
- Race-detector coverage for controller, registry, and lifecycle paths.

### Real Kafka integration tests

- Multiple topics and multiple partitions.
- Topic deletion/recreation, partition expansion, regex topic removal, and logical-cluster identity.
- Two consumer instances in one group and forced rebalances.
- Active-member commits through the owning franz-go client.
- Crash before acknowledgment and redelivery.
- Crash after downstream processing but before commit, producing a safe duplicate.
- Out-of-order worker completion with a lower-offset hole.
- Full checkpoint window proving per-partition pause/resume.
- Offset and timestamp reset with verified live replay after coordinated restart.
- Stale pre-rebalance and pre-reset token rejection.
- API reload/unload without leaked clients or duplicate consumers.
- Kafka unavailable during commit, reset, startup, and shutdown.
- Commit succeeds but its response is lost, plus delayed completion after revocation.
- Redis router unavailable, recovered, and delivering duplicate entries.
- Redis pending-entry recovery, fencing during network partition, and poison/backlog handling.
- Non-Tyk group member detection and rejection of reset.
- Retention truncation and offset gaps while records are in flight.
- Missing acknowledgment expiry, redelivery, operator recovery, and DLQ failure.
- TLS, mTLS, SASL/PLAIN, SCRAM-SHA-256, and SCRAM-SHA-512.

### Full Gateway e2e

The committed suite must run:

```text
real multi-broker Kafka
  -> two real Tyk Gateway instances
  -> tyk_kafka external_ack stream
  -> separately started HTTP worker application
  -> authenticated acknowledgment API
  -> Redis-based cross-instance routing
```

It must verify:

- successful processing advances the correct Kafka next-offset;
- failed processing does not acknowledge or advance Kafka;
- concurrent workers cannot commit past a gap;
- a gateway kill causes safe redelivery on the surviving gateway;
- an acknowledgment sent to the non-owner gateway reaches the owner;
- reset quiesces both gateways and replays exactly from the planned position;
- unauthorized, keyless, forged, expired, and stale control requests fail;
- downstream deduplication handles the expected crash-window duplicate.

Tests use unique topics/groups, polling assertions rather than fixed sleeps, deterministic failure hooks, automatic container cleanup, and captured diagnostics on failure.

### Performance and soak tests

- Throughput and latency compared with Bento `kafka_franz` in `output_ack` mode.
- Memory remains bounded at the configured window across many partitions.
- Slow and permanently missing acknowledgments do not stall unrelated partitions.
- Rebalance stability under sustained load.
- Twenty-four-hour soak with periodic broker, Redis, worker, and gateway restarts.

The checked-in microbenchmarks and bounded fault-injection harness can be run
without external services:

```sh
go test ./ee/middleware/streams/kafka -run '^$' -bench 'BenchmarkKafkaAcknowledgmentBookkeepingComparison|BenchmarkExternalAckOutOfOrderGapClosure|BenchmarkInMemoryDistributedAckRouting' -benchmem
go test ./ee/middleware/streams/kafka -run '^TestExternalAckBoundedSoak$'
TYK_KAFKA_CONTROLLER_SOAK_DURATION=24h go test ./ee/middleware/streams/kafka -run '^TestExternalAckBoundedSoak$' -timeout 25h
```

These are regression and profiling tools, not substitutes for the real
Kafka/Redis/two-Gateway soak topology required by the ship gate:

```sh
TYK_KAFKA_SOAK_DURATION=24h TYK_KAFKA_SOAK_RESTART_INTERVAL=15s go test -tags=dev ./gateway -run '^TestKafkaExternalAckTopologySoak$' -timeout 25h -count=1
```

The exact-offset-correlated tree, with external mode explicitly disabling
franz-go auto-commit and with the cached-Manager analytics race removed, passed
a corrected bounded-history final-tree 3-minute qualification in 202.37s
using a 3-second Gateway restart cadence. Long-run
correctness fixes give child processes a 26-hour lifetime ceiling, issue a
26-hour authorization TTL for the API ID actually loaded by each Gateway,
close each restarted child's log file, and retry committed-offset probes across
transient broker disruption. The 24-hour run is still in progress/uncompleted;
no final passing artifact is recorded here.

### Ship gate

The feature is ready only when:

- all tests above pass in CI and the race detector;
- new-code coverage satisfies the repository quality gate;
- security and threat-model review approves token and control-plane behavior;
- Kafka compatibility is verified against the supported version matrix;
- documentation includes migration, operations, failure semantics, and examples;
- dashboards and alerts exist for uncommitted lag, paused partitions, router backlog, and reset failures;
- VINCI validates the workflow using a release-candidate build;
- normal synchronous Streams behavior and performance show no material regression;
- the implementation is rebased on current master and receives required Innersource, QA, and product approvals.

## Implementation phases

### Phase 0: contract and test fixtures

- Confirm VINCI requires asynchronous acceptance rather than synchronous HTTP completion.
- Agree token transport, acknowledgment response semantics, maximum processing time, batching, expected concurrency, and reset authorization.
- Check in the real Kafka worker fixture and initially failing acceptance tests.

### Phase 1: connector extraction and lifecycle

- Retain `tyk_kafka` registration and reusable franz-go configuration from the PoC.
- Replace copied code where practical with small upstreamable Bento hooks or isolated Tyk packages.
- Remove Sarama offset clients and handlers.
- Give the active connector explicit lifecycle ownership and manager registration.
- Add complete close/reload/dry-run tests.

### Phase 2: local acknowledgment coordinator

- Implement token issuance and validation.
- Implement partition windows, contiguous acknowledgment, commit aggregation, and pause/resume.
- Serialize control operations in the connector event loop.
- Support single-instance `local` routing and complete unit/race coverage.

### Phase 3: rebalances and distributed routing

- Implement assignment epochs and revocation barriers.
- Add Redis Streams owner routing, heartbeat, bounded retention, recovery, and metrics.
- Prove two-gateway rebalance, crash, and non-owner acknowledgment scenarios.

### Phase 4: offset reset control plane

- Implement plan/execute APIs, authorization, audit events, distributed reset lease, quiescence barrier, kadm offset alteration, verification, and restart.
- Support multi-topic/partition and timestamp resolution.

### Phase 5: hardening and customer validation

- Complete TLS/SASL, chaos, performance, soak, upgrade, and supported-Kafka-version testing.
- Publish operator and downstream integration documentation.
- Demo the release candidate to VINCI and incorporate signed-off feedback.

## Decisions and customer validation

The implementation uses these conservative baseline decisions so engineering
and testing can proceed:

- acknowledgment is per record, with a bounded batch API;
- a successful local response means the acknowledgment was applied to the
  window; only a contiguous watermark advancement schedules a Kafka commit,
  and the final API contract must say whether `200` waits for that attempt or
  only confirms local application;
- a queued response means the command was durably appended to its partition
  route, not that an owner has already applied or committed it;
- ordinary retries retain the stable Kafka event identity, while intentional
  replay receives a new replay generation and delivery identity;
- reset requires exclusive ownership of the group and an empty membership;
- missing acknowledgments default to partition-scoped redelivery with bounded
  backoff/attempt/age; exhaustion explicitly pauses or uses a configured
  durable Kafka DLQ;
- production HA uses distributed routing; local routing must enforce singleton
  ownership before it can be enabled.

The following still require product/customer ratification before release:

- Is asynchronous acknowledgment definitely required, or can the downstream hold the delivery response until its transaction commits?
- Must one stream support both acknowledgment modes simultaneously, or only one mode per input?
- What is the maximum downstream processing duration and acceptable duplicate window?
- Are acknowledgments per record only, or must partial batch acknowledgment ship in the first release?
- Is Redis Streams acceptable as a required dependency for multi-gateway routing?
- What durability does the customer expect from `200` versus `202`, and may acknowledgments be retried until Kafka commit is observable?
- What missing-ack deadline and redelivery/pause/DLQ policy is required?
- What are the maximum global record and byte budgets per stream?
- Can Tyk require exclusive ownership of a consumer group for reset?
- Which identity should downstream deduplication use for ordinary retries versus intentional replay?
- Should reset always abandon outstanding work, or optionally wait for a bounded drain period?
- Which Kafka versions and security mechanisms are mandatory for the first release?
- What authorization model maps existing Tyk identities to `kafka:ack` and `kafka:offset-reset`?

No release candidate can be declared until acknowledgment expiry/recovery,
response durability, deduplication versus replay identity, maximum global
in-flight resources, and reset group exclusivity are agreed. These are
customer-visible correctness contracts, not implementation details.

## Current ship answer

PR #8177 and this implementation branch are **not ready to ship**. Focused
local, race, Redis, Kafka, and Gateway tests provide useful engineering
evidence, but they are not substitutes for the complete clean-checkout CI and
release matrix. At minimum, release still requires repeatable clean-CI results
for the observed broker/security matrix and the complete Product-approved
supported-version/platform set;
performance, bounded-memory, and long soak results; extended two-Gateway
crash/network chaos beyond the observed repeated HA/reset cases; repository CI and quality gates; independent security,
architecture, Innersource, QA/DoD, and product approvals; and customer
validation of a release-candidate build. The current-tree Kafka package passed
in 410.004s at 82.0% statement coverage, clearing the local 80% engineering
threshold. That package result does not establish a passing repository
Sonar or CI quality gate. No pending or unobserved test is
represented in this document as passing.

## PoC reuse and removal map

Reuse or adapt:

- `tyk_kafka` component registration and franz-go configuration parsing;
- topic parsing, logging adapter, TLS, SASL, and SCRAM helpers;
- existing partition checkpointer concepts;
- testcontainers Kafka setup;
- per-stream route discovery as a reference for data-plane acknowledgment routing.

Replace or remove:

- the independent Sarama client and all duplicated TLS/SASL translation;
- the shared commit/reset handler;
- raw offset commit requests from downstream applications;
- `disable_auto_commit` as a standalone behavior switch;
- first-topic-only extraction;
- client construction during dry-run and incomplete unload cleanup;
- tests that validate only stored group metadata without an active consumer.
