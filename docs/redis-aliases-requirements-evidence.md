# Redis Aliases Requirements Evidence

<!-- documents STK-REQ-046 SYS-REQ-134 SW-REQ-121 -->

`STK-REQ-046`, `SYS-REQ-134`, and `SW-REQ-121` cover local
`internal/redis` alias behavior.

The executable evidence is `internal/redis/redis_reqproof_test.go`. It verifies
constructor alias identity, sentinel error identity, script constructor
availability, pool and mock constructor availability, and representative
exported type alias compatibility.

This proof slice is intentionally local. It does not claim Redis server
availability, network dialing, command execution, topology correctness,
distributed locking, storage semantics, or final gateway behavior.
