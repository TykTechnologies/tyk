# Certificate Usage Tracker Requirements Evidence

<!-- documents STK-REQ-043 SYS-REQ-131 SW-REQ-118 -->

`STK-REQ-043`, `SYS-REQ-131`, and `SW-REQ-118` cover the local
`internal/certusage` tracker interface contract.

The executable evidence is `internal/certusage/tracker_reqproof_test.go`. It
checks that a local implementation can satisfy the `Tracker` interface and
that the interface preserves the required certificate-used and certificate-API
lookup method signatures.

This evidence does not claim any concrete tracker implementation, certificate
discovery or loading, API lifecycle integration, synchronization behavior,
deletion safety, certificate lifecycle policy, or final gateway behavior.
