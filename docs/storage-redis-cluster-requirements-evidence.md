<!-- documents STK-REQ-099 SYS-REQ-187 SW-REQ-174 -->

`STK-REQ-099`, `SYS-REQ-187`, and `SW-REQ-174` cover RedisCluster storage
adapter behavior in `storage/redis_cluster.go`.

The executable evidence is `storage/redis_cluster_test.go`. It covers the
decomposed local outputs for connection-handler selection, Redis address
derivation, connection-up gating, lazy temporal storage adapter creation, key
prefixing and hash selection, key reads and writes, TTL and expiration
handling, multi-key reads, raw key operations, lock calls, increment and
decrement paths, key scans, key/value filtering, deletes, flushes, pub/sub
receive handling, publish calls, list operations, set operations, sorted-set
operations, controller initialization reporting, key-prefix reporting, and
success/error behavior for mocked or configured storage backends.

This evidence does not claim Redis server availability, Redis clustering
correctness, third-party temporal storage library correctness, distributed lock
safety beyond the wrapper SetIfNotExist call, timing precision for rolling
windows, TTL expiry timing precision, pub/sub delivery guarantees beyond the
exercised handler paths, persistence durability, network partition behavior,
concurrency safety beyond the lazy-storage mutex paths exercised by tests, or
final client-visible gateway behavior outside these RedisCluster storage
adapter tests.
