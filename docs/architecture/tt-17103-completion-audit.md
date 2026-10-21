# TT-17103 completion audit

Audit date: 2026-09-15
Decision: **NOT READY TO SHIP**

## Remaining-gate disposition

After the latest observed runs, the four `MISSING` items are:

- Locally actionable validation: the 24-hour real Kafka/Redis/two-Gateway soak.
- External organizational/customer gates: security/threat-model approval;
  architecture/Innersource/QA/DoD/product approvals; VINCI release-candidate
  validation.

The five `PARTIAL` items are:

- Locally actionable engineering/test work: additional two-member routing
  crash/network chaos and end-to-end broker/HTTP/Redis performance with an
  accepted SLO.
- Mixed local and external: complete repository CI/race execution; expanding
  the observed Kafka 7.5/7.8 and Redis 6/7 compatibility evidence to the
  Product-approved OS/architecture/support matrix; and deploying/accepting the
  dashboards and alerts already backed by metrics.

This is a skeptical, requirement-by-requirement audit of the current working
tree. `PASS` means the implementation and a directly relevant test exist;
`PARTIAL` means useful evidence exists but the stated Definition of Done is
broader or has not been observed across the required matrix; `MISSING` means no
adequate evidence was found. A test name is not evidence that GitHub CI passes.

## Correctness and unit DoD

| Requirement | Status | Exact evidence | Command |
| --- | --- | --- | --- |
| Ordered, duplicate, out-of-order acknowledgment and gap closure | PASS | `partition_window_test.go`: `TestPartitionAckWindowOutOfOrderAndGaps`, `TestPartitionAckWindowConcurrentOutOfOrderAcks`; `external_ack_controller_test.go`: `TestExternalAckControllerOutOfOrderCommit` | `go test ./ee/middleware/streams/kafka -run 'TestPartitionAckWindow|TestExternalAckControllerOutOfOrderCommit'` |
| Never commit past a lower hole; never emit a stale lower commit | PASS | `external_ack_controller.go`; `TestExternalAckControllerRevocationFencesNewerWatermarkDuringFinalCommit`, `TestExternalAckControllerPartitionScopedRebalance` | `go test -race ./ee/middleware/streams/kafka -run 'TestExternalAckController(RevocationFences|PartitionScoped)'` |
| Kafka record offset versus committed next-offset | PASS | `partition_window.go`; `TestPartitionAckWindowAdvancesFromFirstActuallyDeliveredOffset`, `TestPartitionAckWindowAdvancesAcrossKafkaOffsetGaps` | `go test ./ee/middleware/streams/kafka -run 'TestPartitionAckWindowAdvances'` |
| External mode cannot use franz-go periodic auto-commit | PASS | `acknowledgmentGroupCommitOptions` explicitly installs `kgo.DisableAutoCommit()` for external mode. `TestExternalAcknowledgmentE2E` holds delivered records unacknowledged for six seconds, beyond franz-go's five-second default interval, and observes committed offset remain `-1` before explicit gap-safe acknowledgments | `go test ./ee/middleware/streams/kafka -run '^TestExternalAcknowledgmentE2E$' -count=1` |
| Hard per-partition/global record and byte bounds | PASS | `fetch_capacity.go`, controller admission paths; `TestExternalAckControllerCapacityIsHardBounded`, `TestExternalAckControllerRejectsOversizedRecordWithoutReservation`, `TestExternalAckBoundedSoak` | `go test ./ee/middleware/streams/kafka -run 'TestExternalAckControllerCapacity|TestExternalAckControllerRejectsOversized|TestExternalAckBoundedSoak'` |
| Token signing, scope, tamper, expiry, epoch, group/owner, rotation | PASS | `ack_token.go`, `ack_signing_keys.go`; `TestAckTokenCodec*`, `TestSharedAckSigningKeys*`, `TestExternalAckControllerTokenBindsGroupOwnerIssuedAtAndNonce` | `go test ./ee/middleware/streams/kafka -run 'TestAckToken|TestSharedAck|TestExternalAckControllerTokenBinds'` |
| Strict bounded batch API and per-token results | PASS | `api_kafka.go`; `TestAcknowledgmentHandler`, `TestResetExecuteHandlerAndGenericErrors` | `go test ./ee/middleware/streams/kafka -run 'TestAcknowledgmentHandler|TestResetExecuteHandler'` |
| Component-scoped, generation-safe controller registry | PASS | `api_kafka.go`; registry stale-removal and concurrent teardown tests | `go test -race ./ee/middleware/streams/kafka -run 'TestControllerRegistry'` |
| Missing-ack pause, partition redelivery, exponential exhaustion, durable DLQ | PASS | `external_ack_controller.go`, `kafka_dead_letter.go`; deadline tests and `TestKafkaDeadLetterWriter` | `go test ./ee/middleware/streams/kafka -run 'TestExternalAckControllerDeadline|TestExternalAckControllerRedelivery|TestKafkaDeadLetterWriter$'` |
| Ambiguous commit response is idempotently retryable | PASS | duplicate retry fix in `ExternalAckController.Acknowledge`; `TestExternalAckControllerAmbiguousCommitRetryIsIdempotent` | `go test ./ee/middleware/streams/kafka -run TestExternalAckControllerAmbiguousCommitRetryIsIdempotent` |
| Revocation/loss/reset/shutdown fencing and bounded I/O | PASS | controller lifecycle methods; revocation, loss, reset, close, deadline cancellation tests | `go test -race ./ee/middleware/streams/kafka -run 'TestExternalAckController(Revocation|Lost|Reset|Close)'` |
| Offset/timestamp planning, bounds, expiry, empty-group check, partial recovery | PASS | `offset_reset_controller.go`; full `TestLocalOffsetResetController*` set | `go test ./ee/middleware/streams/kafka -run TestLocalOffsetResetController` |
| kadm operation mapping and per-target errors | PASS | `offset_reset_admin_kadm.go`; `TestKadmOffsetResetAdminMapsOperations`, failure tests | `go test ./ee/middleware/streams/kafka -run TestKadmOffsetResetAdmin -short` |
| Durable reset fencing, persistence, audit redaction | PASS | `reset_state_redis.go`, `reset_audit.go`; Redis-state and audit tests. Protocol v2 uses group-scoped leases/generations and exact barrier identity | `go test -race ./ee/middleware/streams/kafka -run '^(TestRedisResetStateStoreRealRedis|TestResetAudit.*)$' -count=1` (Docker required) |
| Manager dry-run/reload/unload singular lifecycle | PASS | `manager_validation_lifecycle_test.go` | `go test ./ee/middleware/streams -run TestManagerValidationDoesNotConnectAndBackgroundLifecycleIsSingular` |
| Local routing singleton ownership | PASS | `TestManagerLocalRoutingSingletonRealRedisE2E` passed in 25.69s through two full Managers, proving live-owner rejection, unload release, crash-expiry rejection, and post-expiry takeover against real Redis | `go test ./ee/middleware/streams -run '^TestManagerLocalRoutingSingletonRealRedisE2E$' -count=1` |
| Metrics/status boundedness and reset audit | PASS | `external_ack_observability.go`, telemetry integration; observability/audit tests | `go test ./ee/middleware/streams/kafka -run 'TestExternalAck(Status|Metrics)|TestResetAudit'` |

## Distributed routing and concurrency DoD

| Requirement | Status | Exact evidence | Command |
| --- | --- | --- | --- |
| Append before `202`, owner fencing, heartbeat/expiry, pending recovery | PASS | `durable_ack_routing.go`, `durable_ack_redis.go`; router/fence/heartbeat tests. The Redis Claim/Heartbeat WATCH conflict repair passed the real race regression | `go test -race ./ee/middleware/streams/kafka -run 'TestDurableAcknowledgment|TestInMemoryDurableAckTransport|TestRedisDurableAckTransportRealRedis'` |
| Redis-native acknowledgment and reset TTLs resist Gateway clock skew | PASS | Real Redis transport/reset-store skew cases passed against `redis:7-alpine`; callers at both +24h and -24h can neither expire ownership/reset leadership or healthy reset participants early nor extend them beyond Redis' native TTL. Reset participant index cleanup is WATCH-fenced against concurrent heartbeat renewal | `go test -race ./ee/middleware/streams/kafka -run '^(TestRedisDurableAckTransportRealRedis|TestRedisResetStateStoreRealRedis)$' -count=1` |
| Poison entries, transient retry/backoff, bounded attempts | PASS | `DurableAckConsumer`; `TestDurableAckConsumerPoisonAndRetryDeadLetter`, transient and processing-error tests | `go test ./ee/middleware/streams/kafka -run TestDurableAckConsumer` |
| Component-global Redis record/byte cap | PASS | Redis transport global counter implementation; concurrent real Redis cases in `TestRedisDurableAckTransportRealRedis` | `go test ./ee/middleware/streams/kafka -run TestRedisDurableAckTransportRealRedis -count=1` |
| Redis outage retains and reclaims pending work | PASS | Docker pause/unpause test was observed passing locally | `go test ./ee/middleware/streams/kafka -run TestRedisDurableAckTransportOutageRecoversPendingEntry -count=1` |
| Distributed owner workers join on revoke/close | PASS | `distributed_ack_owner.go`; lifecycle tests | `go test -race ./ee/middleware/streams/kafka -run TestDistributedAckOwner` |
| Two Kafka members transfer authoritative route ownership | PARTIAL | `TestDistributedAcknowledgmentTwoMemberOwnerTransferE2E` exists; one topology is not the complete crash/network/duplicate matrix | `go test ./ee/middleware/streams/kafka -run TestDistributedAcknowledgmentTwoMemberOwnerTransferE2E -count=1` |
| Full two-Gateway subprocess acknowledgment topology | PASS | `TestKafkaExternalAckTwoGatewaySubprocessE2E` was observed passing twice consecutively; the broader long-duration chaos gate is tracked separately | `go test -tags=dev ./gateway -run '^TestKafkaExternalAckTwoGatewaySubprocessE2E$' -count=2` |
| Full two-Gateway distributed reset with crash takeover | PASS | `TestKafkaExternalAckTwoGatewayDistributedResetE2E` passed twice consecutively in 25.37s and 22.05s on the current reset-v2 credential-attribution/abort-audit tree after group-scoped fencing, exact barrier identity, bounded redacted recovery audit, late-participant enrollment, startup gating, and generation-correct client reconstruction were repaired | `go test -tags=dev ./gateway -run '^TestKafkaExternalAckTwoGatewayDistributedResetE2E$' -count=2` |
| Bounded two-Gateway topology disruption qualification | PASS | After making the producer idempotent, comparing commits with returned Kafka offsets, bounding worker history to 4,096 entries, and reading only its newest 256 entries, the exact-offset-correlated real Kafka/Redis/two-Gateway topology ran for 3 minutes with a 3-second Gateway restart cadence plus explicit Redis and Kafka pause/unpause disruptions and passed in 202.37s on the final reset-v2 tree. External mode explicitly installs `kgo.DisableAutoCommit()` and the cached-Manager analytics race is removed. The harness gives child processes a 26-hour ceiling, provisions 26-hour auth TTL against the actually loaded API ID, closes per-restart logs, and uses retry-safe committed-offset probes. This qualifies the harness but is not the 24-hour soak gate | `TYK_KAFKA_SOAK_DURATION=3m TYK_KAFKA_SOAK_RESTART_INTERVAL=3s TYK_KAFKA_SOAK_DELIVERY_TIMEOUT=15s go test -tags=dev ./gateway -run '^TestKafkaExternalAckTopologySoak$' -count=1 -timeout=6m` |

## Real Kafka, Gateway, and compatibility DoD

| Requirement | Status | Exact evidence | Command |
| --- | --- | --- | --- |
| Real Kafka normal slow-ack/no-commit-before-ack path | PASS | `TestExternalAcknowledgmentE2E`, Gateway acknowledgment E2E | `go test ./ee/middleware/streams/kafka -run TestExternalAcknowledgmentE2E -count=1` |
| Multi-topic/partition lower-hole ordering | PASS | `TestExternalAcknowledgmentMultiTopicPartitionE2E` | `go test ./ee/middleware/streams/kafka -run TestExternalAcknowledgmentMultiTopicPartitionE2E -count=1` |
| Regex/dynamic topic lifecycle | PASS | `TestExternalAcknowledgmentRegexTopicLifecycleE2E` was observed passing and covers initial discovery, partition expansion, discovery of a newly created matching topic, deletion, and removal of deleted-topic controller state | `go test ./ee/middleware/streams/kafka -run TestExternalAcknowledgmentRegexTopicLifecycleE2E -count=1` |
| Real reset and replay through kadm | PASS | connector replay, kadm, and Gateway reset E2Es exist; the Gateway reset test was observed passing twice consecutively | `go test -tags=dev ./gateway -run '^TestKafkaOffsetResetGatewayE2E$' -count=2` |
| Authentication, permissions, forged/stale/expired/keyless rejection | PASS | the real Gateway security cases for forged tokens, expired tokens, and keyless control access were observed passing; middleware permission and positive authenticated tests also pass. Independent security approval is a separate gate | `go test -tags=dev ./gateway -run '^(TestKafkaExternalAcknowledgmentGatewayE2E|TestKafkaControlRoutesForbiddenForKeylessAPI)$' -count=1` |
| Kafka DLQ durable success and failure/no unsafe advance | PASS | real Kafka DLQ writer plus Gateway missing-ack DLQ success/failure cases passed as part of the complete Kafka/Gateway groups; deterministic controller tests prove no source advancement on failed durable write | `go test -tags=dev ./gateway -run '^TestKafkaMissingAcknowledgmentGatewayE2E$' -count=1` |
| Missing-ack redelivery isolation and operator pause recovery | PASS | deterministic controller cases and the full real Gateway missing-ack group were observed passing, including partition redelivery, pause recovery, DLQ, and retention recovery. Long soak remains separate | `go test -tags=dev ./gateway -run '^TestKafkaMissingAcknowledgmentGatewayE2E$' -count=1` |
| Three-broker leader failover | PASS | `TestExternalAcknowledgmentThreeBrokerLeaderFailoverE2E` was observed passing in 49.48s and verifies continued external-ack progress across leader loss. Repeated chaos and version coverage are tracked separately | `go test ./ee/middleware/streams/kafka -run TestExternalAcknowledgmentThreeBrokerLeaderFailoverE2E -count=1` |
| TLS and mTLS positive/negative connector behavior | PASS | `TestExternalAcknowledgmentKafkaTLSE2E` was observed passing in 43.11s; it covers TLS and client-certificate mTLS success plus rogue-CA and missing-client-certificate rejection | `go test ./ee/middleware/streams/kafka -run TestExternalAcknowledgmentKafkaTLSE2E -count=1` |
| SASL PLAIN, SCRAM-SHA-256, and SCRAM-SHA-512 | PASS | `TestExternalAcknowledgmentKafkaSASLE2E` was observed passing all three named subtests against real Kafka; each produces, delivers, acknowledges, and observes the group commit through SASL | `go test ./ee/middleware/streams/kafka -run '^TestExternalAcknowledgmentKafkaSASLE2E/(PLAIN|SCRAM-SHA-256|SCRAM-SHA-512)$' -count=1` |
| Kafka unavailable at startup/commit/reset/shutdown | PASS | `TestExternalAcknowledgmentKafkaOutageLifecycleE2E` covers real broker loss and recovery at startup, commit, and bounded shutdown. `TestDistributedResetBrokerLossAbortsWithoutOffsetAdvance` passed in 19.80s and proves post-plan broker loss triggers abort-resume, leaves the offset unchanged, and completes safely on retry | `go test ./ee/middleware/streams/kafka -run '^(TestExternalAcknowledgmentKafkaOutageLifecycleE2E|TestDistributedResetBrokerLossAbortsWithoutOffsetAdvance)$' -count=1` |
| Retention truncation, `OffsetOutOfRange`, deletion cleanup, and offset gaps | PASS | `TestKafkaMissingAcknowledgmentGatewayE2E/retention_truncation_with_open_window_recovers` was observed passing in 18.954s: real `DeleteRecords` advances log start while a delivery is open, stale in-flight state is fenced, and the partition consumes a post-truncation record. Regex lifecycle and window tests separately cover deleted-topic cleanup and non-arithmetic gaps | `go test -tags=dev ./gateway -run '^TestKafkaMissingAcknowledgmentGatewayE2E/retention_truncation_with_open_window_recovers$' -count=1` |
| API reload/unload with no leaked real Kafka clients or duplicate consumers | PASS | The current-tree enhanced `TestExternalAcknowledgmentReloadReleasesConsumer` passed four real Kafka cycles in 16.06s, proving exactly one live member per cycle, zero members after every stop, controller removal, `stream.Run` termination, franz-go goroutines returning exactly to baseline, Linux `/proc/self/fd` broker sockets returning to a fixture-primed baseline, and safe redelivery | `go test ./ee/middleware/streams/kafka -run '^TestExternalAcknowledgmentReloadReleasesConsumer$' -count=1` |

## Performance, documentation, and release DoD

| Requirement | Status | Exact evidence | Command |
| --- | --- | --- | --- |
| Out-of-order and routing microbenchmarks | PASS | `external_ack_benchmark_test.go`; useful regression data, not an acceptance threshold | `go test ./ee/middleware/streams/kafka -run '^$' -bench 'BenchmarkExternalAckOutOfOrderGapClosure|BenchmarkInMemoryDistributedAckRouting' -benchmem` |
| Bounded fault-injection soak harness | PASS | `TestExternalAckBoundedSoak`, configurable independently by `TYK_KAFKA_CONTROLLER_SOAK_DURATION` | `TYK_KAFKA_CONTROLLER_SOAK_DURATION=10m go test ./ee/middleware/streams/kafka -run TestExternalAckBoundedSoak -timeout 11m` |
| 24-hour real Kafka/Redis/two-Gateway soak | MISSING | the corrected harness passed its 3-minute qualification. A final-tree run then remained healthy for approximately 11 hours, including continuous owner crash/restart churn and successful Redis pause/unpause recovery at hour 8, before it was intentionally stopped by operator request. This is valuable partial evidence but is not a 24-hour pass | `TYK_KAFKA_SOAK_DURATION=24h TYK_KAFKA_SOAK_RESTART_INTERVAL=15s go test -tags=dev ./gateway -run '^TestKafkaExternalAckTopologySoak$' -timeout 25h -count=1` |
| Performance parity/no material regression versus `kafka_franz` | PARTIAL | In addition to the bookkeeping microbenchmark, `TestKafkaAcknowledgmentPerformanceE2E` compares identical real Kafka + TCP HTTP workloads and requires final committed offsets. A 100-record smoke passed at 311.40 rps stock `kafka_franz`, 812.93 rps `tyk_kafka` output-ack, and 445.43 rps external-ack. The sample is intentionally small and no Product-accepted SLO exists | `TYK_KAFKA_PERF=1 TYK_KAFKA_PERF_RECORDS=100 go test ./ee/middleware/streams/kafka -run '^TestKafkaAcknowledgmentPerformanceE2E$' -count=1 -v` |
| Operator/downstream guide and runnable mini-app | PASS | `tt-17103-operator-and-worker-guide.md`, `cmd/tyk-kafka-ack-worker` and its retry/idempotency test | `go test ./cmd/tyk-kafka-ack-worker -count=1` |
| Full clean repository CI and race suite | PARTIAL | the current-tree complete non-short Kafka package passed in 410.004s at 82.0% coverage and the Gateway Kafka-focused group previously passed in 101.760s; current short connector/Streams/worker and tagged Gateway race suites pass. A local `go test -race -short ./... -count=1` attempt exposed unrelated existing `apidef/mcp` and TCP proxy races plus missing Python, shared-port/Redis, and system leak-test environment failures. Two Kafka supervisor assertions made flaky by repository-wide scheduler pressure were corrected to wait for the physical poll gate and then passed 100 race-detector repetitions. Required clean-checkout CI remains unestablished | `go test ./ee/middleware/streams/kafka -count=1`; `go test -race -short ./ee/middleware/streams/kafka ./ee/middleware/streams`; final gate remains `go test -race ./...` in CI |
| New-code coverage threshold | PASS | The complete current-tree non-short Kafka-package run passed in 410.004s with 82.0% statement coverage, including the final reset-v2 implementation and Docker-backed integration paths | `go test ./ee/middleware/streams/kafka -count=1 -coverprofile=kafka.cover` |
| Security/threat-model review | MISSING | tests are not an approval | Required review workflow |
| Architecture, Innersource, QA/DoD, product approvals | MISSING | no approval artifact in this tree | Required GitHub/Jira review workflow |
| Supported Kafka/Redis/platform version matrix | PARTIAL | the real compatibility matrix passed Kafka 7.5 and 7.8 and Redis 6 and 7. This is concrete compatibility evidence, but Product has not defined the complete supported broker/Redis/OS/architecture set, so it cannot prove the release support matrix | `TYK_KAFKA_COMPAT_IMAGE='<approved-image>' go test ./ee/middleware/streams/kafka -run '^TestExternalAcknowledgmentE2E$' -count=1`; run Redis transport/state suites against each approved Redis image |
| Dashboards and production alerts | PARTIAL | metrics/status exist; checked-in Prometheus recording/alert rules and a minimal Grafana dashboard are validated against the actual exported metric names. Deployment, threshold tuning, and alert-routing acceptance remain absent | `go test ./internal/otel -run TestKafkaObservabilityAssetsUseExportedMetrics`; deployment/observability acceptance workflow |
| VINCI release-candidate validation | MISSING | no customer demo/sign-off artifact found | Customer acceptance session and recorded sign-off |

## Reproducible audit commands

Fast local evidence:

```sh
go test -short ./ee/middleware/streams/kafka ./ee/middleware/streams ./cmd/tyk-kafka-ack-worker
go test -race ./ee/middleware/streams/kafka -run 'TestExternalAckController|TestControllerRegistry|TestDistributedAckOwner|TestResetSupervisor|TestResetLeaseKeeper|TestResetBarrierAckIdentity'
go test -tags=dev ./gateway -run 'TestKafkaExternalAcknowledgmentGatewayE2E|TestKafkaMissingAcknowledgmentGatewayE2E|TestKafkaOffsetResetGatewayE2E'
```

Docker evidence (requires Docker and is intentionally not implied by `-short`):

```sh
go test ./ee/middleware/streams/kafka -count=1
go test -tags=dev ./gateway -run 'TestKafkaExternalAckTwoGateway(SubprocessE2E|DistributedResetE2E)' -count=1
```

Final ship evidence must come from a clean checkout and required CI workflows,
not a dirty shared development tree or individually selected passing tests.

Reset protocol v2 is intentionally not rolling-compatible with the old
per-plan lease protocol. Release approval requires a demonstrated coordinated
drain/full-cluster restart with affected Kafka groups empty and no reset in
progress. Old plans are discarded and replanned; rollback uses the same drain
and restart. Mixed-version operation is operationally prohibited and cannot be
technically prevented by v2 nodes because old binaries use a different
namespace. V2 rejects legacy records encountered in its own namespace. Old
Redis keys are retained only for the agreed forensic horizon.
