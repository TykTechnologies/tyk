# Goroutine Debug Record Requirements Evidence

<!-- documents STK-REQ-044 SYS-REQ-132 SW-REQ-119 -->

`STK-REQ-044`, `SYS-REQ-132`, and `SW-REQ-119` cover local
`internal/debug2` goroutine record helper behavior.

The executable evidence is `internal/debug2/goroutine_reqproof_test.go`. It
covers goroutine dump parsing, ignore filtering, diffing a later record against
an earlier record, counting parsed goroutines, and formatted string output.

This evidence does not claim scheduler behavior, goroutine leak policy, runtime
profile completeness, production diagnostics workflow, logging behavior, or
final gateway behavior.
